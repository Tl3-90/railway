import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { authenticate, AuthError } from './auth.js';
import { createConnection, listConnections, getConnection, updateConnection, deleteConnection } from './connections.js';
import { createOperation, listOperations, getOperation, updateOperation, deleteOperation } from './catalog.js';
import { putSecret, getSecret, deleteSecret } from './vault.js';
import { listRemoteTools } from './mcp-connector.js';
import { listGatewayTools, callGatewayTool } from './router.js';
import { adminHtml } from './admin-ui.js';

const BODY_LIMIT = 128 * 1024;

function json(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  response.end(JSON.stringify(body));
}

function errorResponse(response, error) {
  if (response.headersSent) { response.destroy(); return; }
  const status = error instanceof AuthError ? error.status : error instanceof SyntaxError || error instanceof TypeError ? 400 : error?.status === 413 ? 413 : 500;
  if (error instanceof AuthError && error.headers) for (const [name, value] of Object.entries(error.headers)) response.setHeader(name, value);
  json(response, status, { error: status === 400 ? 'Invalid request' : status === 413 ? 'Request too large' : status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Server error' });
}

async function readJson(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new TypeError('Expected JSON');
  if (Number(request.headers['content-length']) > BODY_LIMIT) throw Object.assign(new Error('Too large'), { status: 413 });
  let length = 0;
  const chunks = [];
  for await (const chunk of request) {
    length += chunk.length;
    if (length > BODY_LIMIT) throw Object.assign(new Error('Too large'), { status: 413 });
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Expected object');
  return value;
}

function requireKeys(value, keys) {
  for (const key of Object.keys(value)) if (!keys.includes(key)) throw new TypeError('Unexpected property');
}

async function handleAdmin(request, response, pathname) {
  authenticate(request, 'admin');
  if (pathname === '/admin/connections') {
    if (request.method === 'GET') return json(response, 200, { connections: await listConnections() });
    if (request.method === 'POST') return json(response, 201, { connection: await createConnection(await readJson(request)) });
  }
  if (pathname === '/admin/operations') {
    if (request.method === 'GET') return json(response, 200, { operations: await listOperations() });
    if (request.method === 'POST') {
      const input = await readJson(request);
      const { connectionId, ...operation } = input;
      if ((await getConnection(connectionId))?.kind !== 'api') throw new TypeError('API connection required');
      return json(response, 201, { operation: await createOperation(connectionId, operation) });
    }
  }
  const secretMatch = /^\/admin\/connections\/([0-9a-f-]+)\/secret$/i.exec(pathname);
  if (secretMatch) {
    const connection = await getConnection(secretMatch[1]);
    if (!connection) return json(response, 404, { error: 'Not found' });
    if (request.method === 'PUT') {
      const input = await readJson(request);
      requireKeys(input, ['secret']);
      await putSecret(connection.id, input.secret);
      return json(response, 200, { stored: true });
    }
    if (request.method === 'DELETE') {
      await deleteSecret(connection.id);
      return json(response, 200, { deleted: true });
    }
  }
  const toolsMatch = /^\/admin\/connections\/([0-9a-f-]+)\/tools$/i.exec(pathname);
  if (toolsMatch && request.method === 'GET') {
    const connection = await getConnection(toolsMatch[1]);
    if (!connection) return json(response, 404, { error: 'Not found' });
    if (connection.kind !== 'mcp') return json(response, 400, { error: 'MCP connection required' });
    const credential = connection.authType === 'none' ? null : await getSecret(connection.id);
    if (connection.authType !== 'none' && !credential) return json(response, 409, { error: 'Store a credential first' });
    try {
      const remote = await listRemoteTools(connection, credential);
      const tools = remote.filter(tool => typeof tool?.name === 'string' && /^[A-Za-z0-9_.:/-]{1,128}$/.test(tool.name))
        .slice(0, 100).map(tool => ({ name: tool.name, description: typeof tool.description === 'string' ? tool.description.slice(0, 500) : '' }));
      return json(response, 200, { tools, truncated: remote.length > 100, allowedTools: connection.allowedTools || [] });
    } catch {
      return json(response, 502, { error: 'Unable to discover upstream tools' });
    }
  }
  const connectionMatch = /^\/admin\/connections\/([0-9a-f-]+)$/i.exec(pathname);
  if (connectionMatch) {
    const id = connectionMatch[1];
    if (request.method === 'GET') {
      const connection = await getConnection(id);
      return json(response, connection ? 200 : 404, connection ? { connection } : { error: 'Not found' });
    }
    if (request.method === 'PATCH') {
      const connection = await updateConnection(id, await readJson(request));
      return json(response, connection ? 200 : 404, connection ? { connection } : { error: 'Not found' });
    }
    if (request.method === 'DELETE') {
      const deleted = await deleteConnection(id);
      if (!deleted) return json(response, 404, { error: 'Not found' });
      await deleteSecret(id);
      for (const operation of await listOperations(id)) await deleteOperation(operation.id);
      return json(response, 200, { deleted: true });
    }
  }
  const operationMatch = /^\/admin\/operations\/([0-9a-f-]+)$/i.exec(pathname);
  if (operationMatch) {
    const id = operationMatch[1];
    if (request.method === 'GET') {
      const operation = await getOperation(id);
      return json(response, operation ? 200 : 404, operation ? { operation } : { error: 'Not found' });
    }
    if (request.method === 'PATCH') {
      const operation = await updateOperation(id, await readJson(request));
      return json(response, operation ? 200 : 404, operation ? { operation } : { error: 'Not found' });
    }
    if (request.method === 'DELETE') {
      const deleted = await deleteOperation(id);
      return json(response, deleted ? 200 : 404, deleted ? { deleted } : { error: 'Not found' });
    }
  }
  if (pathname === '/admin/activity' && request.method === 'GET') {
    const { listActivity } = await import('./activity.js');
    return json(response, 200, { activity: await listActivity() });
  }
  return json(response, 404, { error: 'Not found' });
}

async function handleMcp(request, response) {
  const principal = authenticate(request, 'agent');
  if (!['POST', 'GET', 'DELETE'].includes(request.method)) return json(response, 405, { error: 'Method not allowed' });
  const server = new Server({ name: 'personal-mcp-gateway', version: '0.1.0' }, { capabilities: { tools: { listChanged: false } } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: await listGatewayTools() }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    try {
      return await callGatewayTool(request.params.name, request.params.arguments || {}, principal);
    } catch {
      return { content: [{ type: 'text', text: 'Tool call failed' }], isError: true };
    }
  });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true, maxRequestBodySize: BODY_LIMIT });
  await server.connect(transport);
  try { await transport.handleRequest(request, response); }
  finally { await server.close(); }
}

/** A Node HTTP server that can listen on a chosen interface or an ephemeral test port. */
export function createHttpServer() {
  return createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url, 'http://gateway.invalid').pathname;
      if (pathname === '/health' && request.method === 'GET') return json(response, 200, { status: 'ok' });
      if (pathname === '/mcp') return await handleMcp(request, response);
      if (pathname === '/admin' && request.method === 'GET') {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'" });
        return response.end(adminHtml);
      }
      if (pathname.startsWith('/admin/')) return await handleAdmin(request, response, pathname);
      return json(response, 404, { error: 'Not found' });
    } catch (error) { errorResponse(response, error); }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // Fail closed before binding a socket if secrets or persistent storage are absent.
  if (!process.env.GATEWAY_MASTER_KEY || !process.env.GATEWAY_DATA_DIR ||
      !process.env.GATEWAY_AGENT_TOKEN || !process.env.GATEWAY_ADMIN_TOKEN) {
    throw new Error('Gateway configuration is incomplete');
  }
  authenticate({ headers: { authorization: `Bearer ${process.env.GATEWAY_AGENT_TOKEN}` } }, 'agent');
  await getSecret('gateway-startup-key-check');
  const port = Number(process.env.PORT || '3000');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  createHttpServer().listen(port, process.env.HOST || '127.0.0.1', () => {
    process.stdout.write(`Gateway listening on ${process.env.HOST || '127.0.0.1'}:${port}\n`);
  });
}
