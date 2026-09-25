import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { listRemoteTools, callRemoteTool, closeRemoteClients } from '../src/mcp-connector.js';

async function mockMcpServer({ tools = [{ name: 'ping', description: 'Test ping', inputSchema: { type: 'object', properties: {} } }], blockList = false, chunkedList = false } = {}) {
  const requests = [];
  const server = createServer(async (req, res) => {
    if (req.method === 'GET') { res.writeHead(405).end(); return; }
    let body = '';
    for await (const chunk of req) body += chunk;
    const message = JSON.parse(body);
    requests.push({ method: message.method, authorization: req.headers.authorization, apiKey: req.headers['x-service-key'] });
    if (message.method === 'notifications/initialized') { res.writeHead(202).end(); return; }
    if (message.method === 'tools/list' && blockList) return;
    const result = message.method === 'initialize'
      ? { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'upstream-test', version: '1.0.0' } }
      : message.method === 'tools/list'
        ? { tools }
        : { content: [{ type: 'text', text: 'pong' }] };
    const serialized = JSON.stringify({ jsonrpc: '2.0', id: message.id, result });
    if (message.method === 'tools/list' && chunkedList) {
      res.writeHead(200, { 'content-type': 'application/json', 'transfer-encoding': 'chunked' });
      for (let offset = 0; offset < serialized.length; offset += 65_536) res.write(serialized.slice(offset, offset + 65_536));
      res.end();
    } else res.writeHead(200, { 'content-type': 'application/json' }).end(serialized);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, requests, url: `http://127.0.0.1:${server.address().port}/mcp` };
}

test('requires HTTPS unless explicit local development override', async () => {
  delete process.env.ALLOW_INSECURE_UPSTREAMS;
  await assert.rejects(listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: 'http://localhost:1234/mcp' }), /HTTPS/);
  await assert.rejects(listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: 'https://user:pass@example.org/mcp' }), /Invalid MCP endpoint/);
  await assert.rejects(listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: 'ftp://example.org/mcp' }), /HTTPS/);
  await assert.rejects(listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: 'https://127.0.0.1/mcp' }), /Invalid MCP endpoint/);
});

test('discovers and calls a remote tool with a server-held credential', async () => {
  const previous = process.env.ALLOW_INSECURE_UPSTREAMS;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const { server, requests, url } = await mockMcpServer();
  try {
    const connection = { id: 'saved', kind: 'mcp', baseUrl: url, authType: 'bearer' };
    const tools = await listRemoteTools(connection, 'secret-value');
    assert.equal(tools[0].name, 'ping');
    const result = await callRemoteTool(connection, 'ping', {}, 'secret-value');
    assert.equal(result.content[0].text, 'pong');
    assert(requests.some((request) => request.method === 'tools/list'));
    assert(requests.some((request) => request.method === 'tools/call'));
    assert(requests.every((request) => request.authorization === 'Bearer secret-value'));
  } finally {
    await closeRemoteClients();
    server.closeAllConnections();
    server.close();
    if (previous === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = previous;
  }
});

test('does not surface upstream response text or credentials in errors', async () => {
  const previous = process.env.ALLOW_INSECURE_UPSTREAMS;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const server = createServer((_req, res) => res.writeHead(401).end('secret-value rejected'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await assert.rejects(
      listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: `http://127.0.0.1:${server.address().port}/mcp`, authType: 'bearer' }, 'secret-value'),
      (error) => !error.message.includes('secret-value') && /Upstream MCP/.test(error.message),
    );
  } finally {
    server.closeAllConnections();
    server.close();
    if (previous === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = previous;
  }
});

test('uses the shared apiKeyHeader connection mode and rejects unsafe header values', async () => {
  const previous = process.env.ALLOW_INSECURE_UPSTREAMS;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const { server, requests, url } = await mockMcpServer();
  try {
    const connection = { id: 'saved', kind: 'mcp', baseUrl: url, authType: 'apiKeyHeader', headerName: 'X-Service-Key' };
    await listRemoteTools(connection, 'secret-value');
    assert(requests.some((request) => request.method === 'tools/list'));
    assert(requests.every((request) => request.apiKey === 'secret-value'));
    await assert.rejects(listRemoteTools({ ...connection, headerName: 'Host' }, 'secret-value'), /Invalid API key header/);
    await assert.rejects(listRemoteTools(connection, 'secret\r\nX-Bad: value'), /credential is required/);
  } finally {
    await closeRemoteClients();
    server.closeAllConnections();
    server.close();
    if (previous === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = previous;
  }
});

test('bounds the total number and size of discovered tools', async () => {
  const previous = process.env.ALLOW_INSECURE_UPSTREAMS;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const largeListing = await mockMcpServer({ tools: Array.from({ length: 257 }, (_, index) => ({
    name: `tool_${index}`, inputSchema: { type: 'object', properties: {} },
  })) });
  const largeSchema = await mockMcpServer({ tools: [{
    name: 'huge', inputSchema: { type: 'object', description: 'x'.repeat(1_048_576) },
  }] });
  try {
    await assert.rejects(listRemoteTools({ id: 'many', kind: 'mcp', baseUrl: largeListing.url }), /Upstream MCP/);
    await assert.rejects(listRemoteTools({ id: 'size', kind: 'mcp', baseUrl: largeSchema.url }), /Upstream MCP/);
  } finally {
    await closeRemoteClients();
    for (const { server } of [largeListing, largeSchema]) { server.closeAllConnections(); server.close(); }
    if (previous === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = previous;
  }
});

test('aborts oversized streaming MCP responses before returning a tool listing', async () => {
  const previous = process.env.ALLOW_INSECURE_UPSTREAMS;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const { server, url } = await mockMcpServer({ chunkedList: true, tools: [{
    name: 'oversized', inputSchema: { type: 'object', description: 'x'.repeat(3_000_000) },
  }] });
  try {
    await assert.rejects(listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: url }), /Upstream MCP/);
  } finally {
    server.closeAllConnections(); server.close();
    if (previous === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = previous;
  }
});

test('cancels discovery while an upstream tools/list is stalled', async () => {
  const previous = process.env.ALLOW_INSECURE_UPSTREAMS;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const { server, requests, url } = await mockMcpServer({ blockList: true });
  const controller = new AbortController();
  try {
    const pending = listRemoteTools({ id: 'saved', kind: 'mcp', baseUrl: url }, null, { signal: controller.signal });
    while (!requests.some(request => request.method === 'tools/list')) await new Promise(resolve => setTimeout(resolve, 5));
    controller.abort();
    await assert.rejects(pending, /cancelled/);
  } finally {
    server.closeAllConnections(); server.close();
    if (previous === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = previous;
  }
});
