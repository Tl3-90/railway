import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import { createSafeFetch } from './safe-fetch.js';

const CONNECT_TIMEOUT_MS = 15_000;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_TOOL_PAGES = 20;
const DISCOVERY_TIMEOUT_MS = 45_000;
const MAX_REMOTE_TOOLS = 256;
const MAX_REMOTE_TOOL_BYTES = 1_048_576;
const MAX_MCP_RESPONSE_BYTES = 2_097_152;
const activeClients = new Set();

function isPrivateHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (net.isIP(host) === 6) {
    return host === '::1' || host === '::' || host.startsWith('fc') || host.startsWith('fd') ||
      /^fe[89ab]/.test(host) || host.startsWith('::ffff:');
  }
  if (net.isIP(host) !== 4) return false;
  const [a, b] = host.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}

function endpoint(connection) {
  if (!connection || typeof connection !== 'object' || typeof connection.id !== 'string' || !connection.id ||
      connection.kind !== 'mcp' || connection.enabled === false) {
    throw new TypeError('A saved MCP connection is required');
  }
  let url;
  try {
    url = new URL(connection.baseUrl);
  } catch {
    throw new TypeError('Invalid MCP endpoint');
  }
  if (url.protocol !== 'https:' && !(process.env.ALLOW_INSECURE_UPSTREAMS === 'true' && url.protocol === 'http:')) {
    throw new TypeError('MCP endpoint must use HTTPS');
  }
  if (!url.hostname || url.username || url.password || url.search || url.hash ||
      (process.env.ALLOW_INSECURE_UPSTREAMS !== 'true' && isPrivateHost(url.hostname))) {
    throw new TypeError('Invalid MCP endpoint');
  }
  return url;
}

function authHeaders(connection, credential) {
  const authType = connection.authType ?? 'none';
  if (authType === 'none') return {};
  if (typeof credential !== 'string' || !credential.trim() || /[\r\n]/.test(credential)) {
    throw new TypeError('MCP connection credential is required');
  }
  if (authType === 'bearer') return { Authorization: `Bearer ${credential}` };
  if (authType === 'apiKeyHeader') {
    const name = connection.headerName;
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /^(host|content-length|accept|content-type|mcp-|connection|transfer-encoding)/i.test(name)) {
      throw new TypeError('Invalid API key header');
    }
    return { [name]: credential };
  }
  throw new TypeError('Unsupported MCP authentication type');
}

async function bounded(work, timeoutMs, signal) {
  let timer;
  let onAbort;
  try {
    return await Promise.race([
      work,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Upstream MCP operation timed out')), timeoutMs);
        onAbort = () => reject(new Error('Upstream MCP operation cancelled'));
        if (signal?.aborted) onAbort();
        else signal?.addEventListener('abort', onAbort, { once: true });
      }),
    ]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

function boundedResponse(response, abortController) {
  if (!response.body || response.status === 204 || response.status === 205 || response.status === 304) return response;
  const reportedSize = Number(response.headers.get('content-length'));
  if (Number.isFinite(reportedSize) && reportedSize > MAX_MCP_RESPONSE_BYTES) {
    abortController.abort();
    throw new Error('Upstream MCP response exceeded limit');
  }
  let received = 0;
  const stream = response.body.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      received += chunk.byteLength;
      if (received > MAX_MCP_RESPONSE_BYTES) {
        abortController.abort();
        throw new Error('Upstream MCP response exceeded limit');
      }
      controller.enqueue(chunk);
    },
  }));
  return new Response(stream, { status: response.status, statusText: response.statusText, headers: response.headers });
}

async function withRemoteClient(connection, credential, action, deadline, signal) {
  const url = endpoint(connection);
  const headers = authHeaders(connection, credential);
  const client = new Client({ name: 'mcp-gateway', version: '1.0.0' }, { capabilities: {} });
  const safeFetch = createSafeFetch({ allowInsecureUpstreams: process.env.ALLOW_INSECURE_UPSTREAMS === 'true' });
  const abortController = new AbortController();
  const onAbort = () => abortController.abort();
  if (signal?.aborted) onAbort();
  else signal?.addEventListener('abort', onAbort, { once: true });
  activeClients.add(client);
  try {
    if (abortController.signal.aborted) throw new Error('Upstream MCP operation cancelled');
    const transport = new StreamableHTTPClientTransport(url, {
      requestInit: { headers },
      // Authentication headers must never be forwarded to another host by redirects.
      fetch: async (input, init) => {
        const signals = [abortController.signal, init?.signal, input?.signal].filter(Boolean);
        const response = await safeFetch.fetch(input, { ...init, signal: AbortSignal.any(signals) });
        return boundedResponse(response, abortController);
      },
    });
    await bounded(client.connect(transport), Math.min(CONNECT_TIMEOUT_MS, remainingTime(deadline)), abortController.signal);
    return await action(client, abortController.signal);
  } catch (error) {
    if (error?.message === 'Upstream MCP operation timed out' || error?.message === 'Upstream MCP operation cancelled') {
      throw new Error(error.message);
    }
    // SDK/network exceptions may include request headers or response bodies.
    throw new Error('Upstream MCP connection or request failed');
  } finally {
    abortController.abort();
    signal?.removeEventListener('abort', onAbort);
    activeClients.delete(client);
    try { await client.close(); } catch { /* Best effort cleanup. */ }
    try { await safeFetch.close(); } catch { /* Best effort cleanup. */ }
  }
}

function remainingTime(deadline) {
  if (deadline === undefined) return CONNECT_TIMEOUT_MS;
  return Math.max(1, Math.min(REQUEST_TIMEOUT_MS, Math.ceil(deadline - performance.now())));
}

/** Discover tools from a saved remote MCP connection. Never accept a URL from tool arguments. */
export async function listRemoteTools(connection, credential, { signal } = {}) {
  const deadline = performance.now() + DISCOVERY_TIMEOUT_MS;
  return withRemoteClient(connection, credential, async (client, operationSignal) => {
    const tools = [];
    let totalBytes = 0;
    const seenCursors = new Set();
    let cursor;
    for (let page = 0; page < MAX_TOOL_PAGES; page += 1) {
      if (performance.now() >= deadline) throw new Error('Upstream MCP operation timed out');
      const requestTimeout = remainingTime(deadline);
      const result = await bounded(client.listTools(cursor ? { cursor } : undefined, { timeout: requestTimeout }), requestTimeout, operationSignal);
      if (!Array.isArray(result?.tools)) throw new Error('Invalid upstream tool listing');
      for (const tool of result.tools) {
        if (tools.length >= MAX_REMOTE_TOOLS) throw new Error('Upstream tool listing exceeded limit');
        totalBytes += Buffer.byteLength(JSON.stringify(tool), 'utf8');
        if (totalBytes > MAX_REMOTE_TOOL_BYTES) throw new Error('Upstream tool listing exceeded size limit');
        tools.push(tool);
      }
      cursor = result.nextCursor;
      if (!cursor) return tools;
      if (seenCursors.has(cursor)) throw new Error('Repeated upstream cursor');
      seenCursors.add(cursor);
    }
    throw new Error('Upstream tool listing exceeded page limit');
  }, deadline, signal);
}

/** Execute one selected tool on a saved remote MCP connection. */
export async function callRemoteTool(connection, remoteToolName, args = {}, credential) {
  if (typeof remoteToolName !== 'string' || !remoteToolName || remoteToolName.length > 256) {
    throw new TypeError('Invalid remote tool name');
  }
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    throw new TypeError('Remote tool arguments must be an object');
  }
  return withRemoteClient(connection, credential, (client, signal) => bounded(
    client.callTool({ name: remoteToolName, arguments: args }, undefined, { timeout: REQUEST_TIMEOUT_MS }),
    REQUEST_TIMEOUT_MS,
    signal,
  ));
}

/** Close in-flight clients during shutdown. */
export async function closeRemoteClients() {
  await Promise.allSettled([...activeClients].map((client) => client.close()));
  activeClients.clear();
}
