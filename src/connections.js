import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import net from 'node:net';

const FILENAME = 'connections.json';
const MUTABLE_FIELDS = new Set(['name', 'kind', 'baseUrl', 'authType', 'headerName', 'enabled', 'allowedTools']);
const RECORD_FIELDS = new Set([...MUTABLE_FIELDS, 'id', 'createdAt', 'updatedAt']);
let writes = Promise.resolve();

function dataPath() {
  const directory = process.env.GATEWAY_DATA_DIR;
  if (!directory || !path.isAbsolute(directory)) {
    throw new Error('GATEWAY_DATA_DIR must be an absolute path');
  }
  return path.join(directory, FILENAME);
}

function validateId(id) {
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    throw new TypeError('id must be a UUID');
  }
}

function isPrivateIp(hostname) {
  const address = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(address) === 6) {
    const lower = address.toLowerCase();
    return lower === '::1' || lower === '::' || lower.startsWith('fc') || lower.startsWith('fd') || /^fe[89ab]/.test(lower) || lower.startsWith('::ffff:');
  }
  if (net.isIP(address) !== 4) return false;
  const [a, b] = address.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}

function validateUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new TypeError('baseUrl must be a URL string');
  let url;
  try { url = new URL(value); } catch { throw new TypeError('baseUrl must be a valid URL'); }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && process.env.ALLOW_INSECURE_UPSTREAMS === 'true')) {
    throw new TypeError('baseUrl must use HTTPS');
  }
  if (!url.hostname || url.username || url.password || url.search || url.hash) {
    throw new TypeError('baseUrl cannot contain credentials, a query, or a fragment');
  }
  if (process.env.ALLOW_INSECURE_UPSTREAMS !== 'true' &&
      (url.hostname === 'localhost' || url.hostname.endsWith('.localhost') ||
       url.hostname.endsWith('.local') || isPrivateIp(url.hostname))) {
    throw new TypeError('baseUrl cannot target a local or private address');
  }
  return url.toString().replace(/\/$/, '');
}

function validateFields(input, { partial = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new TypeError('connection must be a plain object');
  }
  const keys = Object.keys(input);
  if (partial && !keys.length) throw new TypeError('patch cannot be empty');
  for (const key of keys) if (!MUTABLE_FIELDS.has(key)) throw new TypeError(`unsupported connection field: ${key}`);
  if (!partial || 'name' in input) {
    if (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 100) throw new TypeError('name must be 1–100 characters');
  }
  if (!partial || 'kind' in input) {
    if (!['api', 'mcp'].includes(input.kind)) throw new TypeError('kind must be api or mcp');
  }
  if (!partial || 'authType' in input) {
    if (!['bearer', 'apiKeyHeader', 'none'].includes(input.authType)) throw new TypeError('authType must be bearer, apiKeyHeader, or none');
  }
  if (!partial || 'enabled' in input) {
    if (typeof input.enabled !== 'boolean') throw new TypeError('enabled must be a boolean');
  }
  if (!partial || 'baseUrl' in input) validateUrl(input.baseUrl);
  if ('headerName' in input && (typeof input.headerName !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,99}$/.test(input.headerName))) {
    throw new TypeError('headerName must be an HTTP header name');
  }
  if ('allowedTools' in input && (!Array.isArray(input.allowedTools) || input.allowedTools.length > 100 ||
      input.allowedTools.some(name => typeof name !== 'string' || !/^[A-Za-z0-9_.:/-]{1,128}$/.test(name)) ||
      new Set(input.allowedTools).size !== input.allowedTools.length)) {
    throw new TypeError('allowedTools must contain up to 100 unique MCP tool names');
  }
}

function normalized(input) {
  return {
    name: input.name.trim(), kind: input.kind, baseUrl: validateUrl(input.baseUrl),
    authType: input.authType, ...(input.authType === 'apiKeyHeader' ? { headerName: input.headerName } : {}),
    enabled: input.enabled,
    ...(input.kind === 'mcp' ? { allowedTools: [...(input.allowedTools ?? [])] } : {}),
  };
}

function validateComplete(input) {
  validateFields(input);
  if (input.authType === 'apiKeyHeader' && !input.headerName) throw new TypeError('headerName is required for apiKeyHeader');
  if (input.authType !== 'apiKeyHeader' && input.headerName !== undefined) throw new TypeError('headerName is only valid for apiKeyHeader');
  if (input.kind !== 'mcp' && input.allowedTools !== undefined) throw new TypeError('allowedTools is only valid for MCP connections');
}

async function readRecords() {
  let raw;
  try { raw = await fs.readFile(dataPath(), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.some(record => !record || typeof record !== 'object' ||
    !Object.keys(record).every(key => RECORD_FIELDS.has(key)) || typeof record.id !== 'string')) {
    throw new Error('Invalid connections database');
  }
  return parsed;
}

async function writeRecords(records) {
  const file = dataPath();
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    await fs.writeFile(temporary, JSON.stringify(records, null, 2), { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, file);
  } finally {
    await fs.rm(temporary, { force: true });
  }
}

function mutate(operation) {
  const result = writes.then(operation);
  writes = result.catch(() => {});
  return result;
}

export async function createConnection(input) {
  validateComplete(input);
  const values = normalized(input);
  return mutate(async () => {
    const records = await readRecords();
    const now = new Date().toISOString();
    const record = { id: randomUUID(), ...values, createdAt: now, updatedAt: now };
    records.push(record);
    await writeRecords(records);
    return { ...record };
  });
}

export async function listConnections() {
  await writes;
  return readRecords();
}

export async function getConnection(id) {
  validateId(id);
  const records = await listConnections();
  return records.find(record => record.id === id) ?? null;
}

export async function updateConnection(id, patch) {
  validateId(id);
  validateFields(patch, { partial: true });
  return mutate(async () => {
    const records = await readRecords();
    const index = records.findIndex(record => record.id === id);
    if (index < 0) return null;
    const merged = { ...records[index], ...patch };
    if (patch.authType && patch.authType !== 'apiKeyHeader' && !('headerName' in patch)) delete merged.headerName;
    if (patch.kind === 'api' && !('allowedTools' in patch)) delete merged.allowedTools;
    const mutable = Object.fromEntries([...MUTABLE_FIELDS].filter(key => key in merged).map(key => [key, merged[key]]));
    validateComplete(mutable);
    records[index] = { ...records[index], ...normalized(mutable), updatedAt: new Date().toISOString() };
    if (records[index].authType !== 'apiKeyHeader') delete records[index].headerName;
    if (records[index].kind !== 'mcp') delete records[index].allowedTools;
    await writeRecords(records);
    return { ...records[index] };
  });
}

export async function deleteConnection(id) {
  validateId(id);
  return mutate(async () => {
    const records = await readRecords();
    const index = records.findIndex(record => record.id === id);
    if (index < 0) return false;
    records.splice(index, 1);
    await writeRecords(records);
    return true;
  });
}
