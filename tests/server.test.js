import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { createHttpServer } from '../src/server.js';

test('admin CRUD and MCP endpoint enforce separate tokens and keep secrets write-only', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'gateway-http-'));
  const saved = Object.fromEntries(['GATEWAY_DATA_DIR', 'GATEWAY_MASTER_KEY', 'GATEWAY_ADMIN_TOKEN', 'GATEWAY_AGENT_TOKEN', 'ALLOW_INSECURE_UPSTREAMS'].map(key => [key, process.env[key]]));
  process.env.GATEWAY_DATA_DIR = directory;
  process.env.GATEWAY_MASTER_KEY = randomBytes(32).toString('hex');
  process.env.GATEWAY_ADMIN_TOKEN = randomBytes(32).toString('hex');
  process.env.GATEWAY_AGENT_TOKEN = randomBytes(32).toString('hex');
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  const upstream = createServer(async (req, res) => {
    if (req.method === 'GET') return res.writeHead(405).end();
    let body = '';
    for await (const chunk of req) body += chunk;
    const message = JSON.parse(body);
    if (message.method === 'notifications/initialized') return res.writeHead(202).end();
    const result = message.method === 'initialize'
      ? { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'test-upstream', version: '1' } }
      : { tools: [{ name: 'ping', description: 'A remote tool', inputSchema: { type: 'object', properties: {} } }] };
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const server = createHttpServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const admin = { Authorization: `Bearer ${process.env.GATEWAY_ADMIN_TOKEN}` };
  const agent = { Authorization: `Bearer ${process.env.GATEWAY_AGENT_TOKEN}` };
  const request = (url, method = 'GET', body, headers = admin) => fetch(base + url, {
    method, headers: { ...headers, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body && JSON.stringify(body),
  });
  try {
    assert.equal((await request('/admin/connections', 'GET', null, {})).status, 401);
    assert.equal((await request('/admin/connections', 'GET', null, agent)).status, 403);
    assert.equal((await request('/mcp', 'POST', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } }, admin)).status, 403);
    const createdResponse = await request('/admin/connections', 'POST', { name: 'Example', kind: 'api', baseUrl: 'https://example.com', authType: 'bearer', enabled: true });
    assert.equal(createdResponse.status, 201);
    const { connection } = await createdResponse.json();
    assert.equal((await request(`/admin/connections/${connection.id}/secret`, 'PUT', { secret: 'super-private-key' })).status, 200);
    const listing = await (await request('/admin/connections')).text();
    assert.ok(listing.includes(connection.id));
    assert.ok(!listing.includes('super-private-key'));
    const operationResponse = await request('/admin/operations', 'POST', { connectionId: connection.id, name: 'Fetch status', description: 'Read status', method: 'GET', path: '/status', inputSchema: { type: 'object', properties: {}, additionalProperties: false } });
    assert.equal(operationResponse.status, 201);
    const { operation } = await operationResponse.json();
    assert.equal((await request('/admin/operations')).status, 200);
    const mcpResponse = await request('/admin/connections', 'POST', { name: 'Remote', kind: 'mcp', baseUrl: `http://127.0.0.1:${upstream.address().port}/mcp`, authType: 'none', enabled: true });
    assert.equal(mcpResponse.status, 201);
    const mcp = (await mcpResponse.json()).connection;
    assert.equal((await request(`/admin/connections/${mcp.id}/tools`, 'GET', null, agent)).status, 403);
    const preview = await request(`/admin/connections/${mcp.id}/tools`);
    assert.equal(preview.status, 200);
    assert.deepEqual((await preview.json()).tools.map(tool => tool.name), ['ping']);
    const selected = await request(`/admin/connections/${mcp.id}`, 'PATCH', { allowedTools: ['ping'] });
    assert.deepEqual((await selected.json()).connection.allowedTools, ['ping']);
    const init = await request('/mcp', 'POST', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } }, { ...agent, Accept: 'application/json, text/event-stream' });
    assert.equal(init.status, 200);
    assert.equal((await init.json()).result.serverInfo.name, 'personal-mcp-gateway');
    const tools = await request('/mcp', 'POST', { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, { ...agent, Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18' });
    assert.equal(tools.status, 200);
    const exposed = (await tools.json()).result.tools;
    assert.ok(exposed.some(tool => tool.name.includes(operation.id.replaceAll('-', ''))));
    assert.ok(exposed.some(tool => tool.name.startsWith(`mcp_${mcp.id.replaceAll('-', '')}`)));
    assert.equal((await request(`/admin/connections/${connection.id}`, 'DELETE')).status, 200);
    assert.deepEqual((await (await request('/admin/operations')).json()).operations, []);
  } finally {
    await new Promise(resolve => server.close(resolve));
    upstream.closeAllConnections();
    await new Promise(resolve => upstream.close(resolve));
    await rm(directory, { recursive: true, force: true });
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});
