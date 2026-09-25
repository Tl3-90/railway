import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { promises as fs, constants as fsConstants } from 'node:fs';
import path from 'node:path';

const locks = new Map();

function filename(connectionId) {
  if (typeof connectionId !== 'string' || !connectionId || connectionId.length > 512) {
    throw new TypeError('Invalid connection ID');
  }
  return `${createHash('sha256').update(connectionId, 'utf8').digest('hex')}.json`;
}

/**
 * GATEWAY_MASTER_KEY must be a 32-byte key encoded as 64 hexadecimal characters
 * or canonical base64 (44 characters, normally ending in `=`). Generate once,
 * store outside source control, and back it up securely. Losing or changing it
 * makes existing secrets unreadable. GATEWAY_DATA_DIR selects persistent storage;
 * its default is `<working directory>/data`.
 */
function masterKey() {
  const value = process.env.GATEWAY_MASTER_KEY;
  if (!value) throw new Error('GATEWAY_MASTER_KEY must be configured');
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, 'hex');
  if (/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    const key = Buffer.from(value, 'base64');
    if (key.length === 32 && key.toString('base64') === value) return key;
  }
  throw new Error('GATEWAY_MASTER_KEY must encode exactly 32 bytes');
}

function vaultDir() {
  return path.join(path.resolve(process.env.GATEWAY_DATA_DIR || path.join(process.cwd(), 'data')), 'vault');
}

async function ensureDirectory() {
  const directory = vaultDir();
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Vault directory is invalid');
  await fs.chmod(directory, 0o700);
  return directory;
}

// Serialize operations on a record within this process. The temporary-file
// rename also keeps each record complete if the process stops while writing.
function serialized(record, operation) {
  const previous = locks.get(record) || Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  const settled = current.catch(() => {});
  locks.set(record, settled);
  settled.finally(() => {
    if (locks.get(record) === settled) locks.delete(record);
  });
  return current;
}

/** Encrypt and persist a UTF-8 API token for a connection. */
export async function putSecret(connectionId, secret) {
  const record = filename(connectionId);
  if (typeof secret !== 'string' || secret.length === 0) throw new TypeError('Invalid secret');
  return serialized(record, async () => {
    const key = masterKey();
    const directory = await ensureDirectory();
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(connectionId, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    const payload = JSON.stringify({
      v: 1,
      iv: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    });
    const target = path.join(directory, record);
    const temporary = path.join(directory, `.${record}.${randomBytes(12).toString('hex')}.tmp`);
    try {
      const handle = await fs.open(temporary, 'wx', 0o600);
      try {
        await handle.writeFile(payload, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      await fs.rename(temporary, target);
    } finally {
      await fs.rm(temporary, { force: true }).catch(() => {});
    }
  });
}

/** Return the stored token or null if no token exists. */
export async function getSecret(connectionId) {
  const record = filename(connectionId);
  return serialized(record, async () => {
    const key = masterKey();
    const target = path.join(vaultDir(), record);
    let payload;
    try {
      payload = await fs.readFile(target, { encoding: 'utf8', flag: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW });
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw new Error('Unable to read credential');
    }
    try {
      const parsed = JSON.parse(payload);
      if (parsed.v !== 1) throw new Error('Unknown credential format');
      const nonce = Buffer.from(parsed.iv, 'base64');
      const tag = Buffer.from(parsed.tag, 'base64');
      if (nonce.length !== 12 || tag.length !== 16 || typeof parsed.ciphertext !== 'string') {
        throw new Error('Invalid credential format');
      }
      const decipher = createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAAD(Buffer.from(connectionId, 'utf8'));
      decipher.setAuthTag(tag);
      return Buffer.concat([
        decipher.update(Buffer.from(parsed.ciphertext, 'base64')),
        decipher.final(),
      ]).toString('utf8');
    } catch {
      throw new Error('Unable to decrypt credential');
    }
  });
}

/** Delete a token. Deleting a missing token is safe and idempotent. */
export async function deleteSecret(connectionId) {
  const record = filename(connectionId);
  return serialized(record, async () => {
    const target = path.join(vaultDir(), record);
    try {
      await fs.unlink(target);
    } catch (error) {
      if (error.code !== 'ENOENT') throw new Error('Unable to delete credential');
    }
  });
}
