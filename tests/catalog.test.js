import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import {
  createOperation, deleteOperation, exposedApiToolName, exposedMcpToolName,
  getOperation, listOperations, updateOperation,
} from '../src/catalog.js';

const connectionId = '7c98376d-8934-47ce-8668-4b68cdefe899';
const otherConnectionId = 'c4e609de-b704-4e68-a8c3-a1d3bb209d45';
let directory;

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'catalog-test-'));
  process.env.GATEWAY_DATA_DIR = directory;
});
after(async () => {
  await rm(directory, { recursive: true, force: true });
  delete process.env.GATEWAY_DATA_DIR;
});

function input(overrides = {}) {
  return {
    name: 'Get order', description: 'Read an order', method: 'get', path: '/orders/{id}',
    inputSchema: {
      type: 'object', properties: { id: { type: 'string' }, verbose: { type: 'boolean' } },
      required: ['id'],
    }, ...overrides,
  };
}

test('persists CRUD operations and filters by connection', async () => {
  const first = await createOperation(connectionId, input());
  const second = await createOperation(otherConnectionId, input({ name: 'Another order' }));
  assert.equal(first.method, 'GET');
  assert.equal(first.inputSchema.additionalProperties, false);
  assert.equal((await listOperations()).length, 2);
  assert.deepEqual((await listOperations(connectionId)).map(operation => operation.id), [first.id]);
  assert.deepEqual(await getOperation(first.id), first);
  const changed = await updateOperation(first.id, { enabled: false, description: 'Read selected order' });
  assert.equal(changed.enabled, false);
  assert.equal(changed.id, first.id);
  assert.equal((await getOperation(first.id)).description, 'Read selected order');
  assert.equal(await deleteOperation(first.id), true);
  assert.equal(await deleteOperation(first.id), false);
  assert.equal(await getOperation(first.id), null);
  assert.deepEqual((await listOperations()).map(operation => operation.id), [second.id]);
  assert.equal((await stat(join(directory, 'operations.json'))).mode & 0o777, 0o600);
  assert.equal(JSON.parse(await readFile(join(directory, 'operations.json'), 'utf8')).length, 1);
});

test('rejects unsafe operation definitions', async () => {
  const invalid = [
    input({ path: 'https://api.example.com/orders' }),
    input({ path: '//other-host/orders' }),
    input({ path: '/orders/../admin' }),
    input({ path: '/orders/%2fadmin' }),
    input({ path: '/orders?admin=true' }),
    input({ path: '/orders/{missing}' }),
    input({ method: 'TRACE' }),
    input({ inputSchema: { type: 'object', properties: { url: { type: 'string' } } } }),
    input({ inputSchema: { type: 'object', additionalProperties: true } }),
    input({ inputSchema: { type: 'object', properties: { id: { type: 'not-a-real-json-schema-type' } }, required: ['id'] } }),
    input({ inputSchema: { type: 'object', properties: { id: { $ref: 'https://example.com/schema.json' } }, required: ['id'] } }),
    input({ inputSchema: { type: 'object', properties: { id: { $dynamicRef: '#id' } }, required: ['id'] } }),
    { ...input(), headers: { Authorization: 'secret' } },
  ];
  for (const operation of invalid) await assert.rejects(createOperation(connectionId, operation), TypeError);
});

test('rejects an invalid schema update without modifying the existing operation', async () => {
  const current = await createOperation(connectionId, input());
  await assert.rejects(updateOperation(current.id, {
    inputSchema: { type: 'object', properties: { id: { type: 'invalid' } }, required: ['id'] },
  }), TypeError);
  assert.deepEqual(await getOperation(current.id), current);
});

test('serializes concurrent writes and produces stable distinct tool names', async () => {
  const existingCount = (await listOperations(connectionId)).length;
  const records = await Promise.all(Array.from({ length: 12 }, (_, index) =>
    createOperation(connectionId, input({ name: `Read ${index}` }))));
  assert.equal(new Set(records.map(operation => operation.id)).size, 12);
  assert.equal((await listOperations(connectionId)).length, existingCount + 12);
  assert.equal(new Set(records.map(exposedApiToolName)).size, 12);
  assert.match(exposedMcpToolName(connectionId, 'get_orders'), /^mcp_[a-f0-9]+_[a-f0-9]+$/);
  assert.notEqual(exposedMcpToolName(connectionId, 'get_orders'), exposedMcpToolName(connectionId, 'get_orders2'));
});
