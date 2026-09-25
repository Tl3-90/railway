import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import Ajv from 'ajv';

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const FORBIDDEN_ARGUMENTS = new Set(['url', 'baseurl', 'headers', 'authorization', 'method', 'path']);
const ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ajv = new Ajv({ allErrors: false, strict: false, validateFormats: false });
let writeQueue = Promise.resolve();

function storagePath() {
  return join(process.env.GATEWAY_DATA_DIR || join(process.cwd(), 'data'), 'operations.json');
}

function validateId(id, label = 'id') {
  if (typeof id !== 'string' || !ID_PATTERN.test(id)) throw new TypeError(`${label} must be a UUID`);
  return id;
}

function nonempty(value, label, maximum = 256) {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum) {
    throw new TypeError(`${label} must be a nonempty string of at most ${maximum} characters`);
  }
  return value.trim();
}

function validateSchema(schema) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || schema.type !== 'object') {
    throw new TypeError('inputSchema must be a JSON Schema object with type "object"');
  }
  if (schema.properties !== undefined && (!schema.properties || typeof schema.properties !== 'object' || Array.isArray(schema.properties))) {
    throw new TypeError('inputSchema.properties must be an object');
  }
  const properties = schema.properties || {};
  for (const key of Object.keys(properties)) {
    if (FORBIDDEN_ARGUMENTS.has(key.toLowerCase())) throw new TypeError(`inputSchema cannot expose ${key}`);
  }
  if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some(key => typeof key !== 'string' || !(key in properties)))) {
    throw new TypeError('inputSchema.required must name defined properties');
  }
  if (schema.additionalProperties !== undefined && schema.additionalProperties !== false) {
    throw new TypeError('inputSchema.additionalProperties must be false');
  }
  let plain;
  try {
    plain = JSON.parse(JSON.stringify(schema));
  } catch {
    throw new TypeError('inputSchema must be JSON serializable');
  }
  if (JSON.stringify(plain).length > 65536) throw new TypeError('inputSchema exceeds 64 KiB');
  const normalized = { ...plain, additionalProperties: false };
  function hasExternalReferences(value) {
    if (!value || typeof value !== 'object') return false;
    if (Object.hasOwn(value, '$ref') || Object.hasOwn(value, '$dynamicRef')) return true;
    return Object.values(value).some(hasExternalReferences);
  }
  if (hasExternalReferences(normalized)) throw new TypeError('inputSchema cannot contain $ref or $dynamicRef');
  try { ajv.compile(normalized); }
  catch { throw new TypeError('inputSchema is not supported by the gateway validator'); }
  return normalized;
}

function validatePath(value) {
  const path = nonempty(value, 'path', 2048);
  if (!path.startsWith('/') || path.startsWith('//') || /[\\?#\s]/.test(path) || /%(?:2f|5c|2e|3f|23|00)/i.test(path)) {
    throw new TypeError('path must be a relative API path without query, fragments, or encoded separators');
  }
  if (path.split('/').some(segment => segment === '.' || segment === '..')) throw new TypeError('path cannot traverse directories');
  if (/[{}]/.test(path.replace(/\{[A-Za-z_][A-Za-z0-9_]*\}/g, ''))) {
    throw new TypeError('path placeholders must use {argumentName}');
  }
  return path;
}

function validateOperation(connectionId, input, current) {
  validateId(connectionId, 'connectionId');
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('operation must be an object');
  const allowed = new Set(['name', 'description', 'method', 'path', 'inputSchema', 'enabled']);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new TypeError(`unsupported operation field: ${key}`);
  const merged = { ...current, ...input };
  const name = nonempty(merged.name, 'name', 128);
  const description = nonempty(merged.description, 'description', 1024);
  if (typeof merged.method !== 'string' || !METHODS.has(merged.method.toUpperCase())) throw new TypeError('unsupported HTTP method');
  const method = merged.method.toUpperCase();
  const path = validatePath(merged.path);
  const inputSchema = validateSchema(merged.inputSchema);
  const enabled = merged.enabled === undefined ? true : merged.enabled;
  if (typeof enabled !== 'boolean') throw new TypeError('enabled must be boolean');
  const placeholders = [...path.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map(match => match[1]);
  for (const key of placeholders) {
    if (!Object.hasOwn(inputSchema.properties || {}, key) || !(inputSchema.required || []).includes(key)) {
      throw new TypeError(`path placeholder ${key} must be a required inputSchema property`);
    }
  }
  return { connectionId, name, description, method, path, inputSchema, enabled };
}

async function readOperations() {
  try {
    const operations = JSON.parse(await readFile(storagePath(), 'utf8'));
    if (!Array.isArray(operations)) throw new Error('operation catalog is malformed');
    return operations;
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function saveOperations(operations) {
  const target = storagePath();
  const directory = process.env.GATEWAY_DATA_DIR || join(process.cwd(), 'data');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = `${target}.${randomUUID()}.tmp`;
  try {
    const file = await open(temporary, 'wx', 0o600);
    try {
      await file.writeFile(`${JSON.stringify(operations, null, 2)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, target);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

function mutate(fn) {
  const next = writeQueue.then(async () => {
    const operations = await readOperations();
    const result = fn(operations);
    await saveOperations(operations);
    return result;
  });
  writeQueue = next.catch(() => {});
  return next;
}

export function exposedApiToolName(operation) {
  validateId(operation?.id, 'operation.id');
  return `api_${operation.id.replaceAll('-', '')}`;
}

export function exposedMcpToolName(connectionId, remoteToolName) {
  validateId(connectionId, 'connectionId');
  nonempty(remoteToolName, 'remoteToolName', 512);
  const digest = createHash('sha256').update(remoteToolName).digest('hex').slice(0, 24);
  return `mcp_${connectionId.replaceAll('-', '')}_${digest}`;
}

export async function createOperation(connectionId, input) {
  const validated = validateOperation(connectionId, input);
  return mutate(operations => {
    const record = { id: randomUUID(), ...validated };
    operations.push(record);
    return record;
  });
}

export async function listOperations(connectionId) {
  if (connectionId !== undefined) validateId(connectionId, 'connectionId');
  const operations = await readOperations();
  return connectionId ? operations.filter(record => record.connectionId === connectionId) : operations;
}

export async function getOperation(id) {
  validateId(id);
  return (await readOperations()).find(record => record.id === id) || null;
}

export async function updateOperation(id, patch) {
  validateId(id);
  return mutate(operations => {
    const index = operations.findIndex(record => record.id === id);
    if (index === -1) return null;
    const current = operations[index];
    const validated = validateOperation(current.connectionId, patch, current);
    return (operations[index] = { id, ...validated });
  });
}

export async function deleteOperation(id) {
  validateId(id);
  return mutate(operations => {
    const index = operations.findIndex(record => record.id === id);
    if (index === -1) return false;
    operations.splice(index, 1);
    return true;
  });
}
