import Ajv from 'ajv';
import { getConnection, listConnections } from './connections.js';
import { getSecret } from './vault.js';
import { getOperation, listOperations, exposedApiToolName, exposedMcpToolName } from './catalog.js';
import { invokeApi } from './api-adapter.js';
import { listRemoteTools, callRemoteTool } from './mcp-connector.js';
import { recordActivity } from './activity.js';

const ajv = new Ajv({ allErrors: false, strict: false, validateFormats: false });
const MAX_RESULT_BYTES = 1_048_576;
const MAX_ARGS_BYTES = 65_536;
const DISCOVERY_TIMEOUT_MS = 10_000;
const LIST_TIMEOUT_MS = 15_000;
const DISCOVERY_CONCURRENCY = 4;
const EMPTY_SCHEMA = Object.freeze({ type: 'object', properties: {}, additionalProperties: false });

function errorResult(code, message) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: { code, message } }) }], isError: true };
}

function safeSchema(schema) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || schema.type !== 'object') return EMPTY_SCHEMA;
  try {
    const serialized = JSON.stringify(schema);
    if (serialized.length > MAX_ARGS_BYTES) return null;
    const parsed = JSON.parse(serialized);
    if (JSON.stringify(parsed).includes('"$ref"') || JSON.stringify(parsed).includes('"$dynamicRef"')) return null;
    ajv.compile(parsed);
    return parsed;
  } catch { return null; }
}

function validArguments(args, schema) {
  if (args === null || typeof args !== 'object' || Array.isArray(args) || Object.getPrototypeOf(args) !== Object.prototype) return false;
  let encoded;
  try { encoded = JSON.stringify(args); } catch { return false; }
  if (typeof encoded !== 'string' || encoded.length > MAX_ARGS_BYTES) return false;
  try { return ajv.compile(schema)(args) === true; } catch { return false; }
}

function resultText(data) {
  const value = typeof data === 'string' ? data : JSON.stringify(data);
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_RESULT_BYTES) {
    return errorResult('RESULT_TOO_LARGE', 'Service response exceeded the size limit');
  }
  return { content: [{ type: 'text', text: value }] };
}

async function credential(connection) {
  return connection.authType === 'none' ? null : getSecret(connection.id);
}

function apiTool(connection, operation) {
  const inputSchema = safeSchema(operation.inputSchema);
  if (!inputSchema) return null;
  return {
    name: exposedApiToolName(operation),
    description: `${connection.name}: ${operation.description}`,
    inputSchema,
    connection,
    operation,
    kind: 'api',
  };
}

function mcpTool(connection, remote) {
  if (typeof remote?.name !== 'string' || !remote.name || remote.name.length > 256) return null;
  const inputSchema = safeSchema(remote.inputSchema ?? EMPTY_SCHEMA);
  if (!inputSchema) return null;
  return {
    name: exposedMcpToolName(connection.id, remote.name),
    description: `${connection.name}: ${typeof remote.description === 'string' ? remote.description.slice(0, 1024) : remote.name}`,
    inputSchema,
    connection,
    remoteName: remote.name,
    kind: 'mcp',
  };
}

async function discoverRemote(connection, { signal } = {}) {
  const allowed = new Set(Array.isArray(connection.allowedTools) ? connection.allowedTools : []);
  if (allowed.size === 0) return [];
  if (signal?.aborted) return [];
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, DISCOVERY_TIMEOUT_MS);
  try {
    const secret = await credential(connection);
    if (controller.signal.aborted || connection.authType !== 'none' && !secret) return [];
    const remoteTools = await listRemoteTools(connection, secret, { signal: controller.signal });
    if (controller.signal.aborted) return [];
    return remoteTools.filter(remote => allowed.has(remote?.name)).map(remote => mcpTool(connection, remote)).filter(Boolean);
  } catch { return []; }
  finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

async function discoverTools() {
  const [connections, operations] = await Promise.all([listConnections(), listOperations()]);
  const tools = new Map();
  const remoteConnections = [];
  const operationsByConnection = new Map();
  for (const operation of operations) {
    if (!operationsByConnection.has(operation.connectionId)) operationsByConnection.set(operation.connectionId, []);
    operationsByConnection.get(operation.connectionId).push(operation);
  }
  for (const connection of connections) {
    if (!connection.enabled) continue;
    if (connection.kind === 'api') {
      for (const operation of operationsByConnection.get(connection.id) ?? []) {
        if (operation.enabled) {
          const tool = apiTool(connection, operation);
          if (tool) tools.set(tool.name, tool);
        }
      }
    } else if (connection.kind === 'mcp') {
      if (Array.isArray(connection.allowedTools) && connection.allowedTools.length) remoteConnections.push(connection);
    }
  }
  const deadline = Date.now() + LIST_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LIST_TIMEOUT_MS);
  try {
    for (let offset = 0; offset < remoteConnections.length && Date.now() < deadline; offset += DISCOVERY_CONCURRENCY) {
      const batch = remoteConnections.slice(offset, offset + DISCOVERY_CONCURRENCY);
      const found = await Promise.all(batch.map(connection => discoverRemote(connection, { signal: controller.signal })));
      for (const tool of found.flat()) tools.set(tool.name, tool);
    }
  } finally { clearTimeout(timer); }
  return tools;
}

async function findTool(name) {
  let match = /^api_([0-9a-f]{32})$/.exec(name);
  if (match) {
    const id = match[1].replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
    const operation = await getOperation(id);
    if (!operation?.enabled) return null;
    const connection = await getConnection(operation.connectionId);
    if (!connection?.enabled || connection.kind !== 'api') return null;
    return apiTool(connection, operation);
  }
  match = /^mcp_([0-9a-f]{32})_([0-9a-f]{24})$/.exec(name);
  if (!match) return null;
  const id = match[1].replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
  const connection = await getConnection(id);
  if (!connection?.enabled || connection.kind !== 'mcp' || !connection.allowedTools?.length) return null;
  return (await discoverRemote(connection)).find(tool => tool.name === name) ?? null;
}

/** Discover the enabled tools visible to an AI client. No credentials enter the listing. */
export async function listGatewayTools() {
  return [...(await discoverTools()).values()].map(({ name, description, inputSchema }) => ({ name, description, inputSchema }));
}

/** Dispatch only a tool that is registered and enabled at call time. */
export async function callGatewayTool(name, args, principal) {
  const started = performance.now();
  let connectionId;
  let outcome = 'error';
  let errorCode = 'ERROR';
  try {
    if (principal?.role !== 'agent') {
      errorCode = 'FORBIDDEN';
      return errorResult('FORBIDDEN', 'Agent authorization required');
    }
    if (typeof name !== 'string' || name.length > 128 || !/^(api|mcp)_[a-z0-9_]+$/.test(name)) {
      errorCode = 'NOT_FOUND';
      return errorResult('NOT_FOUND', 'Tool is unavailable');
    }
    const tool = await findTool(name);
    if (!tool) {
      errorCode = 'NOT_FOUND';
      return errorResult('NOT_FOUND', 'Tool is unavailable');
    }
    connectionId = tool.connection.id;
    if (!validArguments(args, tool.inputSchema)) {
      errorCode = 'INVALID_ARGUMENTS';
      return errorResult('INVALID_ARGUMENTS', 'Invalid tool arguments');
    }
    const secret = await credential(tool.connection);
    if (tool.connection.authType !== 'none' && !secret) {
      errorCode = 'UPSTREAM_ERROR';
      return errorResult('UPSTREAM_ERROR', 'Service credential is unavailable');
    }
    let result;
    if (tool.kind === 'api') {
      const response = await invokeApi(tool.connection, tool.operation, args, secret, {
        allowInsecureHttp: process.env.ALLOW_INSECURE_UPSTREAMS === 'true',
        allowPrivateNetwork: process.env.ALLOW_INSECURE_UPSTREAMS === 'true',
      });
      if (!response.ok) {
        errorCode = response.error?.code === 'upstream_timeout' ? 'UPSTREAM_TIMEOUT' :
          response.error?.code === 'invalid_arguments' ? 'INVALID_ARGUMENTS' : 'UPSTREAM_ERROR';
        return errorResult(errorCode, response.error?.message || 'Service request failed');
      }
      result = resultText(response.data);
    } else {
      const response = await callRemoteTool(tool.connection, tool.remoteName, args, secret);
      const encoded = JSON.stringify(response);
      if (Buffer.byteLength(encoded, 'utf8') > MAX_RESULT_BYTES) {
        errorCode = 'UPSTREAM_ERROR';
        return errorResult('RESULT_TOO_LARGE', 'Service response exceeded the size limit');
      }
      result = { content: response.content ?? [], ...(response.isError ? { isError: true } : {}),
        ...(response.structuredContent ? { structuredContent: response.structuredContent } : {}) };
      if (response.isError) errorCode = 'UPSTREAM_ERROR';
    }
    if (!result.isError) outcome = 'success';
    return result;
  } catch {
    errorCode = 'UPSTREAM_ERROR';
    return errorResult('UPSTREAM_ERROR', 'Service is unavailable');
  } finally {
    try {
      await recordActivity({ principal: principal?.role, toolName: name, connectionId,
        outcome, durationMs: performance.now() - started, errorCode });
    } catch { /* Audit storage failures must not disclose sensitive request context. */ }
  }
}
