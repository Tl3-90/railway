import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import { Agent, fetch as undiciFetch } from 'undici';

function ipv4Parts(address) {
  if (isIP(address) !== 4) return null;
  return address.split('.').map(Number);
}

function ipv6Number(address) {
  if (isIP(address) !== 6) return null;
  let normalized = address.toLowerCase();
  const dotted = normalized.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const octets = ipv4Parts(dotted[1]);
    normalized = `${normalized.slice(0, -dotted[1].length)}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const [left, right] = normalized.split('::');
  const before = left ? left.split(':') : [];
  const after = right ? right.split(':') : [];
  const groups = right === undefined ? before : [...before, ...Array(8 - before.length - after.length).fill('0'), ...after];
  if (groups.length !== 8) return null;
  return groups.reduce((acc, group) => acc * 65_536n + BigInt(parseInt(group, 16)), 0n);
}

function inPrefix(value, prefix, bits) {
  return (value >> BigInt(128 - bits)) === (prefix >> BigInt(128 - bits));
}

/** Rejects non-global addresses, including addresses that can route to cloud instance metadata. */
export function isPublicAddress(address) {
  const ipv4 = ipv4Parts(address);
  if (ipv4) {
    const [a, b, c] = ipv4;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168) return false;
    if (a === 192 && (b === 0 || b === 88 && c === 99 || b === 0 && c === 2)) return false;
    if (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  const ipv6 = ipv6Number(address);
  if (ipv6 === null) return false;
  // IPv4-mapped IPv6 must inherit IPv4 policy.
  if (ipv6 >> 32n === 0xffffn) {
    const v4 = Number(ipv6 & 0xffff_ffffn);
    return isPublicAddress(`${v4 >>> 24}.${v4 >>> 16 & 255}.${v4 >>> 8 & 255}.${v4 & 255}`);
  }
  // Public IPv6 unicast lives in 2000::/3. Exclude special-use blocks inside it.
  if (ipv6 >> 125n !== 1n) return false;
  const prefix = text => ipv6Number(text);
  return !inPrefix(ipv6, prefix('2001::'), 23) &&
    !inPrefix(ipv6, prefix('2001:db8::'), 32) &&
    !inPrefix(ipv6, prefix('2002::'), 16);
}

function allowedUrl(input, allowInsecureUpstreams) {
  const url = new URL(input && typeof input === 'object' && typeof input.url === 'string' ? input.url : input);
  if (url.protocol !== 'https:' && !(allowInsecureUpstreams && url.protocol === 'http:')) throw new Error('Unsafe upstream URL');
  if (url.username || url.password || url.hash) throw new Error('Unsafe upstream URL');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!allowInsecureUpstreams &&
      (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || isIP(host) && !isPublicAddress(host))) {
    throw new Error('Unsafe upstream address');
  }
  return url;
}

/**
 * Per-connection fetch with DNS inspection at the actual socket lookup. The validated
 * address is returned to net.connect itself, so a second DNS answer cannot redirect
 * the connection after validation. TLS and Host keep the original hostname.
 */
export function createSafeFetch({
  allowInsecureUpstreams = process.env.ALLOW_INSECURE_UPSTREAMS === 'true',
  lookup = dns.lookup,
} = {}) {
  const dispatcher = new Agent({ connect: {
    lookup(hostname, options, callback) {
      Promise.resolve().then(async () => {
        const found = await lookup(hostname, { all: true, verbatim: true });
        const records = Array.isArray(found) ? found : [found];
        if (!records.length || records.some(record => !record || !isIP(record.address) ||
            !allowInsecureUpstreams && !isPublicAddress(record.address))) {
          throw new Error('Unsafe upstream DNS answer');
        }
        const family = options?.family;
        const eligible = family ? records.filter(record => record.family === family) : records;
        if (!eligible.length) throw new Error('No eligible upstream DNS answer');
        if (options?.all) callback(null, eligible);
        else callback(null, eligible[0].address, eligible[0].family);
      }).catch(error => callback(error));
    },
  } });
  return {
    async fetch(input, init = {}) {
      const url = allowedUrl(input, allowInsecureUpstreams);
      const { dispatcher: _ignoredDispatcher, redirect: _ignoredRedirect, ...requestInit } = init;
      const request = input && typeof input === 'object' && typeof input.url === 'string' ? input : null;
      const inherited = request ? {
        method: request.method,
        headers: request.headers,
        ...(request.body ? { body: request.body, duplex: 'half' } : {}),
        signal: request.signal,
      } : {};
      return undiciFetch(url, { ...inherited, ...requestInit, dispatcher, redirect: 'manual' });
    },
    close() { return dispatcher.close(); },
  };
}

// Environment override may be enabled after import by local development/test setup.
// Keep one pool per mode rather than creating a new socket pool for every tool call.
const defaultClients = new Map();
export function safeFetch(input, init) {
  const allowInsecureUpstreams = process.env.ALLOW_INSECURE_UPSTREAMS === 'true';
  if (!defaultClients.has(allowInsecureUpstreams)) {
    defaultClients.set(allowInsecureUpstreams, createSafeFetch({ allowInsecureUpstreams }));
  }
  return defaultClients.get(allowInsecureUpstreams).fetch(input, init);
}
