import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { putSecret, getSecret, deleteSecret } from '../src/vault.js';

test('vault encrypts tokens, restricts files, and supports overwrite and deletion', async () => {
  const originalDir = process.env.GATEWAY_DATA_DIR;
  const originalKey = process.env.GATEWAY_MASTER_KEY;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gateway-vault-'));
  const key = randomBytes(32).toString('hex');
  process.env.GATEWAY_DATA_DIR = directory;
  process.env.GATEWAY_MASTER_KEY = key;
  try {
    const id = 'shopify/account';
    const record = path.join(directory, 'vault', `${createHash('sha256').update(id).digest('hex')}.json`);
    assert.equal(await getSecret(id), null);
    await putSecret(id, 'private-api-key-1');
    assert.equal(await getSecret(id), 'private-api-key-1');
    const onDisk = await fs.readFile(record, 'utf8');
    assert.ok(!onDisk.includes('private-api-key-1'));
    assert.equal((await fs.stat(record)).mode & 0o777, 0o600);
    assert.equal((await fs.stat(path.dirname(record))).mode & 0o777, 0o700);
    await putSecret(id, 'private-api-key-2');
    assert.equal(await getSecret(id), 'private-api-key-2');
    await putSecret('other', 'other-value');
    assert.equal(await getSecret('other'), 'other-value');
    await deleteSecret(id);
    await deleteSecret(id);
    assert.equal(await getSecret(id), null);
    assert.equal(await getSecret('other'), 'other-value');
  } finally {
    if (originalDir === undefined) delete process.env.GATEWAY_DATA_DIR;
    else process.env.GATEWAY_DATA_DIR = originalDir;
    if (originalKey === undefined) delete process.env.GATEWAY_MASTER_KEY;
    else process.env.GATEWAY_MASTER_KEY = originalKey;
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('vault rejects tampering, wrong key, and invalid inputs without leaking tokens', async () => {
  const originalDir = process.env.GATEWAY_DATA_DIR;
  const originalKey = process.env.GATEWAY_MASTER_KEY;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gateway-vault-'));
  process.env.GATEWAY_DATA_DIR = directory;
  process.env.GATEWAY_MASTER_KEY = randomBytes(32).toString('base64');
  try {
    await assert.rejects(putSecret('../bad', ''), /Invalid secret/);
    await assert.rejects(putSecret('', 'value'), /Invalid connection ID/);
    await putSecret('first', 'top-secret-token');
    const record = path.join(directory, 'vault', `${createHash('sha256').update('first').digest('hex')}.json`);
    const original = await fs.readFile(record, 'utf8');
    const modified = JSON.parse(original);
    modified.tag = randomBytes(16).toString('base64');
    await fs.writeFile(record, JSON.stringify(modified));
    await assert.rejects(getSecret('first'), /Unable to decrypt credential/);
    await fs.writeFile(record, original);
    process.env.GATEWAY_MASTER_KEY = randomBytes(32).toString('base64');
    await assert.rejects(getSecret('first'), error =>
      error.message === 'Unable to decrypt credential' && !error.message.includes('top-secret-token'));
    process.env.GATEWAY_MASTER_KEY = randomBytes(10).toString('base64');
    await assert.rejects(getSecret('first'), /GATEWAY_MASTER_KEY must encode exactly 32 bytes/);
  } finally {
    if (originalDir === undefined) delete process.env.GATEWAY_DATA_DIR;
    else process.env.GATEWAY_DATA_DIR = originalDir;
    if (originalKey === undefined) delete process.env.GATEWAY_MASTER_KEY;
    else process.env.GATEWAY_MASTER_KEY = originalKey;
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('operations on one credential are serialized', async () => {
  const originalDir = process.env.GATEWAY_DATA_DIR;
  const originalKey = process.env.GATEWAY_MASTER_KEY;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gateway-vault-'));
  process.env.GATEWAY_DATA_DIR = directory;
  process.env.GATEWAY_MASTER_KEY = randomBytes(32).toString('hex');
  try {
    const writes = Array.from({ length: 20 }, (_, i) => putSecret('same', `token-${i}`));
    await Promise.all(writes);
    assert.equal(await getSecret('same'), 'token-19');
    await Promise.all([deleteSecret('same'), putSecret('same', 'final')]);
    assert.equal(await getSecret('same'), 'final');
  } finally {
    if (originalDir === undefined) delete process.env.GATEWAY_DATA_DIR;
    else process.env.GATEWAY_DATA_DIR = originalDir;
    if (originalKey === undefined) delete process.env.GATEWAY_MASTER_KEY;
    else process.env.GATEWAY_MASTER_KEY = originalKey;
    await fs.rm(directory, { recursive: true, force: true });
  }
});
