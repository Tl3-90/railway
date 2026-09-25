import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { authenticate, AuthError } from '../src/auth.js';

const agentToken = randomBytes(32).toString('base64url');
const adminToken = randomBytes(32).toString('base64url');

function withTokens(fn) {
  const oldAgent = process.env.GATEWAY_AGENT_TOKEN;
  const oldAdmin = process.env.GATEWAY_ADMIN_TOKEN;
  process.env.GATEWAY_AGENT_TOKEN = agentToken;
  process.env.GATEWAY_ADMIN_TOKEN = adminToken;
  try { fn(); } finally {
    if (oldAgent === undefined) delete process.env.GATEWAY_AGENT_TOKEN;
    else process.env.GATEWAY_AGENT_TOKEN = oldAgent;
    if (oldAdmin === undefined) delete process.env.GATEWAY_ADMIN_TOKEN;
    else process.env.GATEWAY_ADMIN_TOKEN = oldAdmin;
  }
}

const request = token => ({ headers: { authorization: `Bearer ${token}` } });
const fails = (action, status) => assert.throws(action, error => error instanceof AuthError && error.status === status);

test('accepts only the corresponding role and handles Web and Node headers', () => withTokens(() => {
  assert.deepEqual(authenticate(request(agentToken), 'agent'), { role: 'agent' });
  assert.deepEqual(authenticate(new Request('https://example.com/mcp', {
    headers: { Authorization: `bearer ${adminToken}` },
  }), 'admin'), { role: 'admin' });
  fails(() => authenticate(request(adminToken), 'agent'), 403);
  fails(() => authenticate(request(agentToken), 'admin'), 403);
}));

test('rejects missing, malformed, and incorrect credentials without echoing them', () => withTokens(() => {
  fails(() => authenticate({ headers: {} }, 'agent'), 401);
  fails(() => authenticate({ headers: { authorization: agentToken } }, 'agent'), 401);
  fails(() => authenticate(request('wrong-token'), 'agent'), 401);
  fails(() => authenticate({ headers: { authorization: `Bearer ${agentToken}, Bearer ${adminToken}` } }, 'agent'), 401);
  try { authenticate(request('wrong-token'), 'agent'); } catch (error) {
    assert.deepEqual(error.headers, { 'WWW-Authenticate': 'Bearer' });
    assert.doesNotMatch(error.message, /wrong-token/);
  }
}));

test('fails closed on missing, short, or shared environment tokens', () => withTokens(() => {
  delete process.env.GATEWAY_AGENT_TOKEN;
  fails(() => authenticate(request(adminToken), 'admin'), 503);
  process.env.GATEWAY_AGENT_TOKEN = 'short';
  fails(() => authenticate(request(adminToken), 'admin'), 503);
  process.env.GATEWAY_AGENT_TOKEN = adminToken;
  fails(() => authenticate(request(adminToken), 'admin'), 503);
}));

test('rejects unknown authorization role', () => withTokens(() => {
  assert.throws(() => authenticate(request(agentToken), 'other'), TypeError);
}));
