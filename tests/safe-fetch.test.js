import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createSafeFetch, isPublicAddress } from '../src/safe-fetch.js';

test('classifies public and internal IPv4 and IPv6 addresses', () => {
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isPublicAddress(address), true, address);
  }
  for (const address of ['127.0.0.1', '10.0.0.1', '172.16.2.3', '192.168.1.2', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '192.0.2.1', '198.51.100.1', '203.0.113.1',
    '::1', 'fe80::1', 'fc00::1', '2001:db8::1', '2002:c0a8:0101::1', '::ffff:127.0.0.1']) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('blocks mixed public/private DNS answers at connect time', async () => {
  const client = createSafeFetch({ lookup: async () => [
    { address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 },
  ] });
  try {
    await assert.rejects(client.fetch('https://safe.example.test/resource'), /fetch failed/);
  } finally { await client.close(); }
});

test('blocks literal private targets and insecure schemes before DNS lookup', async () => {
  let lookups = 0;
  const client = createSafeFetch({ lookup: async () => { lookups++; return []; } });
  try {
    await assert.rejects(client.fetch('http://safe.example.test'), /Unsafe upstream URL/);
    await assert.rejects(client.fetch('https://169.254.169.254/latest/meta-data'), /Unsafe upstream address/);
    await assert.rejects(client.fetch('https://localhost'), /Unsafe upstream address/);
    assert.equal(lookups, 0);
  } finally { await client.close(); }
});

test('local override pins custom DNS result and does not follow redirect', async () => {
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    if (req.url === '/redirect') { res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data' }); res.end(); }
    else { res.writeHead(200); res.end('ok'); }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  let lookups = 0;
  const client = createSafeFetch({ allowInsecureUpstreams: true, lookup: async (host, options) => {
    lookups++;
    assert.equal(host, 'api.example.test');
    assert.equal(options.all, true);
    return [{ address: '127.0.0.1', family: 4 }];
  } });
  try {
    const response = await client.fetch(new Request(`http://api.example.test:${port}/redirect`), { redirect: 'follow' });
    assert.equal(response.status, 302);
    await response.body?.cancel();
    assert.equal(requests, 1);
    assert.equal(lookups, 1);
  } finally {
    await client.close();
    server.close();
    await once(server, 'close');
  }
});
