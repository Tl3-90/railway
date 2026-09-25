import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  createConnection, listConnections, getConnection, updateConnection, deleteConnection,
} from '../src/connections.js';

const base = { name: 'Example', kind: 'api', baseUrl: 'https://api.example.com/v1', authType: 'bearer', enabled: true };

test('persists metadata, updates, and deletes', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-connections-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    const item = await createConnection(base);
    assert.match(item.id, /^[0-9a-f-]{36}$/);
    assert.deepEqual(await getConnection(item.id), item);
    assert.equal((await listConnections()).length, 1);
    const updated = await updateConnection(item.id, { name: 'Renamed', authType: 'apiKeyHeader', headerName: 'X-API-Key' });
    assert.equal(updated.name, 'Renamed');
    assert.equal(updated.headerName, 'X-API-Key');
    assert.equal(updated.createdAt, item.createdAt);
    const none = await updateConnection(item.id, { authType: 'none' });
    assert.equal('headerName' in none, false);
    assert.deepEqual(JSON.parse(await readFile(path.join(dir, 'connections.json'), 'utf8')), [none]);
    assert.equal(await deleteConnection(item.id), true);
    assert.equal(await deleteConnection(item.id), false);
    assert.equal(await getConnection(item.id), null);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});

test('rejects credentials, unsafe URLs, and invalid metadata', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-connections-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    await assert.rejects(createConnection({ ...base, apiKey: 'secret' }), /unsupported connection field/);
    await assert.rejects(createConnection({ ...base, baseUrl: 'http://api.example.com' }), /HTTPS/);
    await assert.rejects(createConnection({ ...base, baseUrl: 'https://127.0.0.1/' }), /local or private/);
    await assert.rejects(createConnection({ ...base, baseUrl: 'https://user:pass@api.example.com' }), /credentials/);
    await assert.rejects(createConnection({ ...base, authType: 'apiKeyHeader' }), /headerName is required/);
    await assert.rejects(createConnection({ ...base, enabled: 'true' }), /boolean/);
    assert.deepEqual(await listConnections(), []);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});

test('serializes concurrent creates and preserves all records', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-connections-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    const records = await Promise.all(Array.from({ length: 20 }, (_, i) => createConnection({ ...base, name: `Service ${i}` })));
    assert.equal((await listConnections()).length, 20);
    assert.equal(new Set(records.map(record => record.id)).size, 20);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP tool selection starts empty, persists changes, and is MCP only', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-connections-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    const mcp = await createConnection({ ...base, kind: 'mcp' });
    assert.deepEqual(mcp.allowedTools, []);
    const updated = await updateConnection(mcp.id, { allowedTools: ['search', 'vendor.get_item'] });
    assert.deepEqual((await getConnection(mcp.id)).allowedTools, ['search', 'vendor.get_item']);
    assert.deepEqual(updated.allowedTools, ['search', 'vendor.get_item']);
    await assert.rejects(updateConnection(mcp.id, { allowedTools: ['search', 'search'] }), /unique/);
    await assert.rejects(updateConnection(mcp.id, { allowedTools: ['bad name'] }), /unique MCP tool names/);
    const api = await updateConnection(mcp.id, { kind: 'api' });
    assert.equal('allowedTools' in api, false);
    await assert.rejects(updateConnection(mcp.id, { allowedTools: ['search'] }), /only valid for MCP/);
    await assert.rejects(createConnection({ ...base, allowedTools: [] }), /only valid for MCP/);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});
