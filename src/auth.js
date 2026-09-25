import { createHash, timingSafeEqual } from 'node:crypto';

export class AuthError extends Error {
  constructor(status) {
    super(status === 403 ? 'Forbidden' : status === 503 ? 'Authentication unavailable' : 'Unauthorized');
    this.name = 'AuthError';
    this.status = status;
    if (status === 401) this.headers = { 'WWW-Authenticate': 'Bearer' };
  }
}

function configuredTokens() {
  const agent = process.env.GATEWAY_AGENT_TOKEN;
  const admin = process.env.GATEWAY_ADMIN_TOKEN;
  // Tokens should be generated from at least 32 random bytes, e.g. randomBytes(32).toString('base64url').
  // Length is a minimum check; applications cannot infer entropy from a supplied string.
  const valid = value => typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') >= 32 &&
    /^[\x21-\x7e]+$/.test(value) && !value.includes(',');
  if (!valid(agent) || !valid(admin) || agent === admin) throw new AuthError(503);
  return { agent, admin };
}

function authorizationHeader(request) {
  const headers = request?.headers;
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get('authorization');
  const value = headers.authorization ?? headers.Authorization;
  return typeof value === 'string' ? value : undefined;
}

function matches(presented, expected) {
  const left = createHash('sha256').update(presented).digest();
  const right = createHash('sha256').update(expected).digest();
  return timingSafeEqual(left, right);
}

/** Authenticate a Request or Node IncomingMessage for an exact agent/admin role. */
export function authenticate(request, role) {
  if (role !== 'agent' && role !== 'admin') throw new TypeError('role must be agent or admin');
  const configured = configuredTokens();
  const header = authorizationHeader(request);
  const match = typeof header === 'string' && /^Bearer ([\x21-\x7e]+)$/i.exec(header);
  if (!match || match[1].includes(',')) throw new AuthError(401);

  // Compare against both tokens for each request, independent of the role being requested.
  const isAgent = matches(match[1], configured.agent);
  const isAdmin = matches(match[1], configured.admin);
  if (role === 'agent' && isAgent) return Object.freeze({ role: 'agent' });
  if (role === 'admin' && isAdmin) return Object.freeze({ role: 'admin' });
  throw new AuthError(isAgent || isAdmin ? 403 : 401);
}
