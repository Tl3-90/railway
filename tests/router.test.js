import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createConnection, updateConnection } from '../src/connections.js';
import { createOperation, updateOperation, exposedApiToolName, exposedMcpToolName } from '../src/catalog.js';
import { putSecret } from '../src/vault.js';
import { closeRemoteClients } from '../src/mcp-connector.js';
import { listGatewayTools, callGatewayTool } from '../src/router.js';

test('exposes a saved API operation, calls it with server-held secret, and honors disabling', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'gateway-router-'));
  const original = { data: process.env.GATEWAY_DATA_DIR, key: process.env.GATEWAY_MASTER_KEY, insecure: process.env.ALLOW_INSECURE_UPSTREAMS };
  process.env.GATEWAY_DATA_DIR = directory;
  process.env.GATEWAY_MASTER_KEY = randomBytes(32).toString('hex');
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  let calls = 0;
  const server = createServer((request, response) => {
    calls++;
    assert.equal(request.url, '/v1/items/abc');
    assert.equal(request.headers.authorization, 'Bearer private-token');
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ id: 'abc' }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const connection = await createConnection({ name: 'Example', kind: 'api', baseUrl: `http://127.0.0.1:${server.address().port}/v1`, authType: 'bearer', enabled: true });
    const operation = await createOperation(connection.id, {
      name: 'Get item', description: 'Get a selected item', method: 'GET', path: '/items/{id}',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false }, enabled: true,
    });
    await putSecret(connection.id, 'private-token');
    const name = exposedApiToolName(operation);
    const exposed = await listGatewayTools();
    assert.deepEqual(exposed.map(tool => tool.name), [name]);
    assert.doesNotMatch(JSON.stringify(exposed), /private-token/);

    const successful = await callGatewayTool(name, { id: 'abc' }, { role: 'agent' });
    assert.equal(successful.isError, undefined);
    assert.deepEqual(JSON.parse(successful.content[0].text), { id: 'abc' });
    for (const [args, principal] of [[{ id: 123 }, { role: 'agent' }], [{ id: 'abc' }, { role: 'admin' }], [{ id: 'abc', url: 'https://elsewhere' }, { role: 'agent' }]]) {
      assert.equal((await callGatewayTool(name, args, principal)).isError, true);
    }
    assert.equal(calls, 1);
    await updateOperation(operation.id, { enabled: false });
    assert.equal((await callGatewayTool(name, { id: 'abc' }, { role: 'agent' })).isError, true);
    assert.equal((await listGatewayTools()).length, 0);
    await updateOperation(operation.id, { enabled: true });
    await updateConnection(connection.id, { enabled: false });
    assert.equal((await callGatewayTool(name, { id: 'abc' }, { role: 'agent' })).isError, true);
    assert.equal(calls, 1);

    const log = await readFile(path.join(directory, 'activity.jsonl'), 'utf8');
    assert.doesNotMatch(log, /private-token|abc|https:\/\//);
    assert.equal(log.trim().split('\n').length, 6);
  } finally {
    server.closeAllConnections();
    server.close();
    if (original.data === undefined) delete process.env.GATEWAY_DATA_DIR;
    else process.env.GATEWAY_DATA_DIR = original.data;
    if (original.key === undefined) delete process.env.GATEWAY_MASTER_KEY;
    else process.env.GATEWAY_MASTER_KEY = original.key;
    if (original.insecure === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS;
    else process.env.ALLOW_INSECURE_UPSTREAMS = original.insecure;
    await rm(directory, { recursive: true, force: true });
  }
});

test('remote MCP tools are denied by default and only selected names can be listed or called', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'gateway-router-mcp-'));
  const old = { data: process.env.GATEWAY_DATA_DIR, insecure: process.env.ALLOW_INSECURE_UPSTREAMS };
  process.env.GATEWAY_DATA_DIR = directory;
  process.env.ALLOW_INSECURE_UPSTREAMS = 'true';
  let calls = 0;
  const server = createServer(async (request, response) => {
    if (request.method === 'GET') { response.writeHead(405).end(); return; }
    let body = '';
    for await (const chunk of request) body += chunk;
    const message = JSON.parse(body);
    if (message.method === 'notifications/initialized') { response.writeHead(202).end(); return; }
    const result = message.method === 'initialize'
      ? { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'upstream', version: '1' } }
      : message.method === 'tools/list'
        ? { tools: ['selected', 'unselected'].map(name => ({ name, inputSchema: { type: 'object', properties: {} } })) }
        : (calls++, { content: [{ type: 'text', text: message.params.name }] });
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const connection = await createConnection({ name: 'Remote', kind: 'mcp', baseUrl: `http://127.0.0.1:${server.address().port}/mcp`, authType: 'none', enabled: true });
    const selected = exposedMcpToolName(connection.id, 'selected');
    const unselected = exposedMcpToolName(connection.id, 'unselected');
    assert.deepEqual(await listGatewayTools(), []);
    assert.equal((await callGatewayTool(selected, {}, { role: 'agent' })).isError, true);
    await updateConnection(connection.id, { allowedTools: ['selected'] });
    assert.deepEqual((await listGatewayTools()).map(tool => tool.name), [selected]);
    assert.equal((await callGatewayTool(unselected, {}, { role: 'agent' })).isError, true);
    assert.equal((await callGatewayTool(selected, {}, { role: 'agent' })).content[0].text, 'selected');
    assert.equal(calls, 1);
    await updateConnection(connection.id, { allowedTools: [] });
    assert.equal((await callGatewayTool(selected, {}, { role: 'agent' })).isError, true);
  } finally {
    await closeRemoteClients();
    server.closeAllConnections();
    server.close();
    if (old.data === undefined) delete process.env.GATEWAY_DATA_DIR; else process.env.GATEWAY_DATA_DIR = old.data;
    if (old.insecure === undefined) delete process.env.ALLOW_INSECURE_UPSTREAMS; else process.env.ALLOW_INSECURE_UPSTREAMS = old.insecure;
    await rm(directory, { recursive: true, force: true });
  }
});
