import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { recordActivity, listActivity } from '../src/activity.js';

const connectionId = '1d0f84e2-8eb8-483c-b36c-18dbd34e09d1';

test('records a bounded event and ignores payloads and secrets', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-activity-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    await recordActivity({
      principal: 'agent', toolName: 'shopify_orders', connectionId,
      outcome: 'success', durationMs: 12.8,
      args: { token: 'SECRET_ARG' }, headers: { Authorization: 'SECRET_HEADER' },
      payload: 'SECRET_PAYLOAD', errorCode: 'SECRET_ERROR',
    });
    const target = path.join(dir, 'activity.jsonl');
    const raw = await readFile(target, 'utf8');
    assert.equal(raw.includes('SECRET'), false);
    assert.deepEqual((await listActivity())[0], {
      timestamp: JSON.parse(raw).timestamp, principal: 'agent',
      toolName: 'shopify_orders', connectionId, outcome: 'success', durationMs: 13,
    });
    assert.equal((await stat(target)).mode & 0o777, 0o600);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});

test('redacts unsafe identifiers and arbitrary error messages', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-activity-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    await recordActivity({ principal: 'https://secret.example/key', toolName: 'Bearer SECRET',
      connectionId: 'SECRET', outcome: 'error', durationMs: 999999999,
      errorCode: 'token=SECRET', error: new Error('SECRET') });
    assert.deepEqual((await listActivity())[0], {
      timestamp: (await listActivity())[0].timestamp, principal: '[redacted]',
      toolName: '[redacted]', connectionId: '[redacted]', outcome: 'error',
      durationMs: 86400000, errorCode: 'ERROR',
    });
    assert.equal((await readFile(path.join(dir, 'activity.jsonl'), 'utf8')).includes('SECRET'), false);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});

test('serializes parallel writes and lists most recent first', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'gateway-activity-'));
  process.env.GATEWAY_DATA_DIR = dir;
  try {
    await Promise.all(Array.from({ length: 25 }, (_, i) => recordActivity({
      principal: 'agent', toolName: `tool_${i}`, connectionId, outcome: 'success', durationMs: i,
    })));
    assert.equal((await listActivity({ limit: 3 })).length, 3);
    assert.equal((await listActivity({ limit: 1 }))[0].toolName, 'tool_24');
    assert.equal((await listActivity({ limit: 25 })).length, 25);
    await assert.rejects(listActivity({ limit: 1001 }), /limit/);
  } finally {
    delete process.env.GATEWAY_DATA_DIR;
    await rm(dir, { recursive: true, force: true });
  }
});
