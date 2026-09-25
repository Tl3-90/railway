import test from 'node:test';
import assert from 'node:assert/strict';
import { invokeApi } from '../src/api-adapter.js';

const connection = { id: 'service', name: 'Example', kind: 'api', baseUrl: 'https://api.example.test/v1', authType: 'bearer', enabled: true };
const operation = {
  id: 'read', connectionId: 'service', name: 'get_item', description: 'Read item', method: 'GET',
  path: '/items/{itemId}', enabled: true,
  inputSchema: { type: 'object', properties: { itemId: { type: 'string' }, filter: { type: 'string' } }, required: ['itemId'] },
};

test('uses configured origin and credentials; maps declared path and query arguments', async () => {
  let seen;
  const result = await invokeApi(connection, operation, { itemId: 'a b', filter: 'open' }, 'secret-token', {
    fetchImpl: async (url, init) => { seen = { url, init }; return new Response(JSON.stringify({ id: 'a b' }), { headers: { 'content-type': 'application/json' } }); },
  });
  assert.deepEqual(result, { ok: true, status: 200, contentType: 'application/json', data: { id: 'a b' } });
  assert.equal(seen.url, 'https://api.example.test/v1/items/a%20b?filter=open');
  assert.equal(seen.init.headers.authorization, 'Bearer secret-token');
  assert.equal(seen.init.redirect, 'manual');
});

test('POST maps declared inputs into JSON, with API key in configured header', async () => {
  let seen;
  const api = { ...connection, authType: 'apiKeyHeader', headerName: 'X-API-Key' };
  const post = { ...operation, method: 'POST', path: '/items', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } };
  const result = await invokeApi(api, post, { name: 'Alpha' }, 'key-123', {
    fetchImpl: async (url, init) => { seen = { url, init }; return new Response('created', { status: 201 }); },
  });
  assert.equal(result.status, 201);
  assert.equal(seen.init.body, '{"name":"Alpha"}');
  assert.equal(seen.init.headers['X-API-Key'], 'key-123');
  assert.equal(seen.init.headers['content-type'], 'application/json');
});

test('rejects arbitrary tool-supplied routing and undeclared arguments', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw Error('Unexpected call'); };
  const result = await invokeApi(connection, operation, { itemId: '42', url: 'https://attacker.test', headers: {} }, 'secret', { fetchImpl });
  assert.equal(result.error.code, 'invalid_arguments');
  assert.equal(calls, 0);
});

test('rejects insecure, private, and malformed routing without sending a request', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw Error('Unexpected call'); };
  for (const baseUrl of ['http://api.example.test', 'https://localhost', 'https://169.254.169.254', 'https://10.0.0.1']) {
    const result = await invokeApi({ ...connection, baseUrl }, operation, { itemId: '42' }, 'secret', { fetchImpl });
    assert.equal(result.error.code, 'invalid_configuration');
  }
  const traversal = await invokeApi(connection, operation, { itemId: '..' }, 'secret', { fetchImpl });
  assert.equal(traversal.error.code, 'invalid_arguments');
  assert.equal(calls, 0);
});

test('rejects redirects and sanitizes upstream failure without exposing secrets', async () => {
  const redirect = await invokeApi(connection, operation, { itemId: '42' }, 'secret', {
    fetchImpl: async () => new Response(null, { status: 302, headers: { location: 'https://attacker.test' } }),
  });
  assert.deepEqual(redirect, { ok: false, status: 302, error: { code: 'upstream_redirect', message: 'Service returned a redirect' } });
  const failed = await invokeApi(connection, operation, { itemId: '42' }, 'secret', {
    fetchImpl: async () => { throw Error('secret downstream details'); },
  });
  assert.equal(failed.error.code, 'upstream_unavailable');
  assert.doesNotMatch(JSON.stringify(failed), /secret/);
});

test('limits response size and timeout', async () => {
  const oversized = await invokeApi(connection, operation, { itemId: '42' }, 'secret', {
    maxResponseBytes: 4, fetchImpl: async () => new Response('12345'),
  });
  assert.equal(oversized.error.code, 'response_too_large');
  const timedOut = await invokeApi(connection, operation, { itemId: '42' }, 'secret', {
    timeoutMs: 10,
    fetchImpl: async (_url, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(Error('aborted')), { once: true })),
  });
  assert.equal(timedOut.error.code, 'upstream_timeout');
});
