import { constants } from 'node:fs';
import { promises as fs } from 'node:fs';
import path from 'node:path';

const FILENAME = 'activity.jsonl';
const MAX_READ_BYTES = 2 * 1024 * 1024;
const MAX_LIMIT = 1000;
const ERROR_CODES = new Set([
  'AUTH', 'FORBIDDEN', 'INVALID_ARGUMENTS', 'NOT_FOUND', 'UPSTREAM_ERROR',
  'UPSTREAM_TIMEOUT', 'RATE_LIMIT', 'INTERNAL_ERROR', 'ERROR',
]);
let writes = Promise.resolve();

function filePath() {
  const directory = process.env.GATEWAY_DATA_DIR;
  if (!directory || !path.isAbsolute(directory)) {
    throw new Error('GATEWAY_DATA_DIR must be an absolute path');
  }
  return path.join(directory, FILENAME);
}

function safeIdentifier(value, maxLength = 128) {
  if (typeof value !== 'string' || !value || value.length > maxLength ||
      !/^[A-Za-z0-9_.:-]+$/.test(value) || value === '.' || value === '..') {
    return '[redacted]';
  }
  return value;
}

function safePrincipal(value) {
  return value === 'admin' || value === 'agent' ? value : '[redacted]';
}

function safeConnectionId(value) {
  return typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
    ? value.toLowerCase() : '[redacted]';
}

function safeErrorCode(value) {
  return typeof value === 'string' && ERROR_CODES.has(value) ? value : 'ERROR';
}

function normalize(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('activity must be an object');
  }
  const { principal, toolName, connectionId, outcome, durationMs, errorCode } = input;
  if (outcome !== 'success' && outcome !== 'error') {
    throw new TypeError('outcome must be success or error');
  }
  if (!Number.isFinite(durationMs) || durationMs < 0) {
    throw new TypeError('durationMs must be a non-negative finite number');
  }
  return {
    timestamp: new Date().toISOString(),
    principal: safePrincipal(principal),
    toolName: safeIdentifier(toolName),
    connectionId: safeConnectionId(connectionId),
    outcome,
    durationMs: Math.min(Math.round(durationMs), 86_400_000),
    ...(outcome === 'error' ? { errorCode: safeErrorCode(errorCode) } : {}),
  };
}

export async function recordActivity(input) {
  const event = normalize(input);
  const operation = writes.then(async () => {
    const target = filePath();
    await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND |
      (constants.O_NOFOLLOW ?? 0);
    const file = await fs.open(target, flags, 0o600);
    try {
      await file.chmod(0o600);
      await file.writeFile(`${JSON.stringify(event)}\n`, 'utf8');
    } finally {
      await file.close();
    }
    return event;
  });
  writes = operation.catch(() => {});
  return operation;
}

export async function listActivity({ limit = 100 } = {}) {
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    throw new TypeError(`limit must be an integer from 1 to ${MAX_LIMIT}`);
  }
  await writes;
  const target = filePath();
  let file;
  try { file = await fs.open(target, 'r'); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  try {
    const { size } = await file.stat();
    const bytes = Math.min(size, MAX_READ_BYTES);
    const buffer = Buffer.alloc(bytes);
    const { bytesRead } = await file.read(buffer, 0, bytes, size - bytes);
    let lines = buffer.subarray(0, bytesRead).toString('utf8');
    if (size > bytes) lines = lines.slice(lines.indexOf('\n') + 1);
    return lines.trimEnd().split('\n').filter(Boolean).slice(-limit).reverse().map(line => JSON.parse(line));
  } finally {
    await file.close();
  }
}
