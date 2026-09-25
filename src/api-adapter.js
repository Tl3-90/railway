import { safeFetch } from './safe-fetch.js';

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function fail(code, message, status = null) {
  return { ok: false, status, error: { code, message } };
}

function isPrivateHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1' || host === '::' || host.startsWith('fe80:') || host.startsWith('fc') || host.startsWith('fd')) return true;
  if (host.startsWith('::ffff:')) return isPrivateHost(host.slice(7));
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  const parts = host.split('.').map(Number);
  if (parts.some(part => part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}

function validateBaseUrl(baseUrl, options) {
  if (typeof baseUrl !== 'string') throw new Error('invalid_configuration');
  const url = new URL(baseUrl);
  if (url.protocol !== 'https:' && !(options.allowInsecureHttp === true && url.protocol === 'http:')) {
    throw new Error('invalid_configuration');
  }
  if (url.username || url.password || url.search || url.hash || isPrivateHost(url.hostname) && options.allowPrivateNetwork !== true) {
    throw new Error('invalid_configuration');
  }
  return url;
}

function validateArgs(args, schema) {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) throw new Error('invalid_arguments');
  if (!schema || schema.type !== 'object' || !schema.properties ||
      typeof schema.properties !== 'object' || Array.isArray(schema.properties)) throw new Error('invalid_configuration');
  for (const key of Object.keys(args)) {
    if (!Object.hasOwn(schema.properties, key) || !FIELD_NAME.test(key)) throw new Error('invalid_arguments');
  }
  for (const key of schema.required || []) {
    if (!Object.hasOwn(args, key)) throw new Error('invalid_arguments');
  }
  return Object.keys(args);
}

function queryValue(value) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'number' && Number.isFinite(value) || typeof value === 'boolean') return String(value);
  throw new Error('invalid_arguments');
}

function makeUrl(base, path, args, used) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.includes('?') || path.includes('#') || path.includes('\\')) {
    throw new Error('invalid_configuration');
  }
  const substituted = path.replace(/\{([^{}]+)\}/g, (_, key) => {
    if (!FIELD_NAME.test(key) || !Object.hasOwn(args, key)) throw new Error('invalid_arguments');
    const value = queryValue(args[key]);
    if (value === '.' || value === '..' || value.includes('/') || value.includes('\\')) throw new Error('invalid_arguments');
    used.add(key);
    return encodeURIComponent(value);
  });
  if (/[{}]/.test(substituted) || substituted.split('/').some(s => s === '.' || s === '..')) throw new Error('invalid_configuration');
  const prefix = base.pathname.replace(/\/+$/, '');
  const url = new URL(`${prefix}${substituted}`, base);
  if (url.origin !== base.origin || !url.pathname.startsWith(`${prefix}/`) && url.pathname !== prefix) throw new Error('invalid_configuration');
  return url;
}

async function boundedResponse(response, maxBytes) {
  const length = response.headers?.get?.('content-length');
  if (length && Number(length) > maxBytes) throw new Error('response_too_large');
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error('response_too_large');
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
    if (size > maxBytes) await response.body.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/** Calls one administrator-configured API operation. Never accepts request routing or headers from tool arguments. */
export async function invokeApi(connection, operation, args, credential, options = {}) {
  const fetchImpl = options.fetchImpl ?? safeFetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000 ||
      !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 10_485_760) {
    return fail('invalid_configuration', 'API operation is misconfigured');
  }
  let base, url, method, fields, used;
  try {
    if (!connection || !operation || connection.enabled === false || operation.enabled === false ||
        connection.kind !== 'api' || operation.connectionId !== connection.id) throw new Error('invalid_configuration');
    const localOverride = process.env.ALLOW_INSECURE_UPSTREAMS === 'true';
    base = validateBaseUrl(connection.baseUrl, {
      allowInsecureHttp: localOverride || options.allowInsecureHttp,
      allowPrivateNetwork: localOverride || options.allowPrivateNetwork,
    });
    method = String(operation.method || '').toUpperCase();
    if (!METHODS.has(method)) throw new Error('invalid_configuration');
    fields = validateArgs(args, operation.inputSchema);
    used = new Set();
    url = makeUrl(base, operation.path, args, used);
  } catch (error) {
    const code = error.message === 'invalid_arguments' ? 'invalid_arguments' : 'invalid_configuration';
    return fail(code, code === 'invalid_arguments' ? 'Invalid tool arguments' : 'API operation is misconfigured');
  }

  const headers = { accept: 'application/json, text/plain;q=0.9' };
  if (connection.authType === 'bearer') {
    if (typeof credential !== 'string' || !credential || /[\r\n]/.test(credential)) return fail('invalid_configuration', 'API operation is misconfigured');
    headers.authorization = `Bearer ${credential}`;
  } else if (connection.authType === 'apiKeyHeader') {
    if (typeof credential !== 'string' || !credential || /[\r\n]/.test(credential) ||
        !HEADER_NAME.test(connection.headerName || '') || /^(authorization|host|content-length|cookie|proxy-authorization)$/i.test(connection.headerName)) {
      return fail('invalid_configuration', 'API operation is misconfigured');
    }
    headers[connection.headerName] = credential;
  } else if (connection.authType !== 'none') {
    return fail('invalid_configuration', 'API operation is misconfigured');
  }

  const remaining = fields.filter(field => !used.has(field));
  let body;
  try {
    if (method === 'GET' || method === 'HEAD') {
      for (const field of remaining) {
        const value = args[field];
        if (Array.isArray(value)) value.forEach(item => url.searchParams.append(field, queryValue(item)));
        else url.searchParams.append(field, queryValue(value));
      }
    } else if (remaining.length) {
      body = JSON.stringify(Object.fromEntries(remaining.map(field => [field, args[field]])));
      headers['content-type'] = 'application/json';
    }
  } catch {
    return fail('invalid_arguments', 'Invalid tool arguments');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url.toString(), {
      method, headers, body, signal: controller.signal, redirect: 'manual',
    });
    if (response.status >= 300 && response.status < 400) return fail('upstream_redirect', 'Service returned a redirect', response.status);
    if (!response.ok) return fail('upstream_error', 'Service request failed', response.status);
    const rawType = response.headers?.get?.('content-type') || '';
    const raw = await boundedResponse(response, maxResponseBytes);
    if (/\b(?:application\/json|[^;]+\+json)\b/i.test(rawType)) {
      try { return { ok: true, status: response.status, contentType: 'application/json', data: raw ? JSON.parse(raw) : null }; }
      catch { return fail('invalid_response', 'Service returned invalid JSON', response.status); }
    }
    return { ok: true, status: response.status, contentType: 'text/plain', data: raw };
  } catch (error) {
    if (error.message === 'response_too_large') return fail('response_too_large', 'Service response exceeded the size limit');
    if (controller.signal.aborted) return fail('upstream_timeout', 'Service request timed out');
    return fail('upstream_unavailable', 'Service request failed');
  } finally {
    clearTimeout(timer);
  }
}
