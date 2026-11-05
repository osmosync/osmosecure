import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { HttpClient } from '../src/http.js';
import { silentLogger } from '../src/lib/log.js';
import { guardedLookup, makeGuardedLookup } from '../src/lib/netguard.js';

const HOSTS_OK = async () => ['93.184.216.34'];
const reply = (status: number, body: string, headers: Record<string, string> = {}) => new Response(body, { status, headers });

function countingServer(): Promise<{ port: number; hits: () => number; close: () => Promise<void> }> {
  let n = 0;
  return new Promise((resolve) => {
    const srv = http.createServer((_req, res) => {
      n++;
      res.end('local-secret');
    });
    srv.listen(0, '127.0.0.1', () =>
      resolve({ port: (srv.address() as AddressInfo).port, hits: () => n, close: () => new Promise((r) => srv.close(() => r())) }),
    );
  });
}

test('F9b-a rebinding: public answer first then 127.0.0.1 never connects to the local server', async () => {
  const srv = await countingServer();
  try {
    let calls = 0;
    // pre-check lookup says public; the connect-time resolver rebinds to loopback
    const connectResolver = async () => {
      calls++;
      return [
        { address: '93.184.216.34', family: 4 },
        { address: '127.0.0.1', family: 4 },
      ];
    };
    const client = new HttpClient('ua', silentLogger, undefined, undefined, async () => {}, { lookup: HOSTS_OK, connectResolver });
    await assert.rejects(() => client.request(`http://rebind.example.com:${srv.port}/`, {}, { timeoutMs: 3000 }), /request blocked.*private address/);
    assert.ok(calls >= 1);
    assert.equal(srv.hits(), 0);
  } finally {
    await srv.close();
  }
});

test('F9b-b guardedLookup: public-only answers pass in both shapes; any private or empty answer is refused', async () => {
  const ask = (resolve: () => Promise<{ address: string; family: number }[]>, all: boolean) =>
    new Promise<{ err: Error | null; res?: unknown; fam?: number }>((done) =>
      makeGuardedLookup(resolve)('h.example.com', { all }, (err, res, fam) => done({ err, res, fam })),
    );
  const pub = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 },
  ];
  const allRes = await ask(pub, true);
  assert.equal(allRes.err, null);
  assert.equal((allRes.res as unknown[]).length, 2);
  const one = await ask(pub, false);
  assert.equal(one.res, '93.184.216.34');
  assert.equal(one.fam, 4);
  const mixed = await ask(async () => [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.5', family: 4 }], true);
  assert.match(mixed.err?.message ?? '', /private address/);
  assert.match((await ask(async () => [], true)).err?.message ?? '', /no usable address/);
  // the real exported lookup refuses a loopback literal without touching the network
  const real = await new Promise<Error | null>((done) => guardedLookup('127.0.0.1', { all: true }, (err) => done(err)));
  assert.match(real?.message ?? '', /private address/);
  // NOT TESTED: an end-to-end connection to a public address, which needs the real internet.
});

test('F9b-c redirect to a host that resolves privately is refused at the hop and never fetched', async () => {
  const seen: string[] = [];
  const fake = (async (url: string | URL | Request) => {
    seen.push(String(url));
    return String(url).startsWith('https://feed.example.com/') ? reply(302, '', { location: 'https://sneaky.example.net/x' }) : reply(200, 'leak');
  }) as typeof fetch;
  const lookup = async (h: string) => (h === 'sneaky.example.net' ? ['10.0.0.5'] : ['93.184.216.34']);
  const client = new HttpClient('ua', silentLogger, undefined, fake, async () => {}, { lookup });
  await assert.rejects(() => client.request('https://feed.example.com/start'), /request blocked.*private address/);
  assert.deepEqual(seen, ['https://feed.example.com/start']);
});

test('F9b-d allowPrivateNetwork true still connects to 127.0.0.1; default client refuses it', async () => {
  const srv = await countingServer();
  try {
    const client = new HttpClient('ua', silentLogger, undefined, undefined, async () => {}, { allowPrivateNetwork: true });
    const res = await client.request(`http://127.0.0.1:${srv.port}/`, {}, { timeoutMs: 3000 });
    assert.equal(res.body, 'local-secret');
    assert.equal(srv.hits(), 1);
    const strict = new HttpClient('ua', silentLogger, undefined, undefined, async () => {}, {});
    await assert.rejects(() => strict.request(`http://127.0.0.1:${srv.port}/`), /blocked/);
    assert.equal(srv.hits(), 1);
  } finally {
    await srv.close();
  }
});
