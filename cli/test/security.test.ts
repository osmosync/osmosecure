import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { parseConfig } from '../src/config.js';
import { collectRss, parseFeed } from '../src/feeds/rss.js';
import { bumpCommand, branchFor, defaultExec, publishFix, slug, startFix, updateCommand, type Exec } from '../src/fix.js';
import { assertLoopbackHost, handleFixRequest, isValidFindingKey, MAX_BODY_BYTES, startFixServer } from '../src/fix-server.js';
import { HttpClient } from '../src/http.js';
import { silentLogger } from '../src/lib/log.js';
import { assertPublicUrl, isPrivateAddress } from '../src/lib/netguard.js';
import { createNotifiers } from '../src/notify/index.js';
import { signBody, verifySignature } from '../src/remediate.js';
import { StateStore } from '../src/state.js';
import { parseTriageReply } from '../src/triage/schema.js';
import { scrubSecrets } from '../src/triage/scrub.js';
import type { Finding, Logger } from '../src/types.js';

const SECRET = 'a-long-enough-test-secret-0123456789';
const tmp = (p: string) => realpathSync(mkdtempSync(path.join(tmpdir(), `osmosecure-sec-${p}-`)));
const HOSTS_OK = async () => ['93.184.216.34'];

// ---------------------------------------------------------------- 1. fix-server

function signedPost(port: number, body: string, opts: { chunked?: boolean; ts?: string; secret?: string } = {}): Promise<{ status: number; body: string }> {
  const ts = opts.ts ?? String(Math.floor(Date.now() / 1000));
  return new Promise((resolve, reject) => {
    const headers: Record<string, string | number> = {
      'x-osmosecure-timestamp': ts,
      'x-osmosecure-signature': signBody(body, opts.secret ?? SECRET, ts),
    };
    if (!opts.chunked) headers['content-length'] = Buffer.byteLength(body);
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/fix', headers }, (res) => {
      let out = '';
      res.on('data', (d) => (out += d));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: out }));
    });
    req.on('error', reject);
    if (opts.chunked) for (let i = 0; i < body.length; i += 8192) req.write(body.slice(i, i + 8192));
    req.end(opts.chunked ? undefined : body);
  });
}

async function withServer(fn: (port: number, dataDir: string, queued: string[]) => Promise<void>, prep?: (dataDir: string) => void): Promise<void> {
  const dataDir = tmp('srv');
  prep?.(dataDir);
  const config = parseConfig({ dataDir }, dataDir);
  const queued: string[] = [];
  const server = startFixServer(config, SECRET, async (k) => void queued.push(k), silentLogger);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    await fn((server.address() as AddressInfo).port, dataDir, queued);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}

test('SEC-01 fix-server: loopback only (host guard, real bind, short secret refused)', async () => {
  for (const ok of ['127.0.0.1', '::1', 'localhost']) assertLoopbackHost(ok);
  for (const bad of ['0.0.0.0', '::', '', '10.0.0.5', 'example.com', '127.0.0.1.evil.test']) assert.throws(() => assertLoopbackHost(bad), /loopback/);
  const dataDir = tmp('bind');
  assert.throws(() => startFixServer(parseConfig({ dataDir, fix: { server: { host: '0.0.0.0' } } }, dataDir), SECRET, async () => {}, silentLogger), /loopback/);
  assert.throws(() => startFixServer(parseConfig({ dataDir }, dataDir), 'short', async () => {}, silentLogger), /at least 16/);
  const config = parseConfig({ dataDir }, dataDir);
  const server = startFixServer(config, SECRET, async () => {}, silentLogger);
  await new Promise<void>((r) => server.listen(0, config.fix.server.host, r));
  assert.equal((server.address() as AddressInfo).address, '127.0.0.1');
  await new Promise((r) => server.close(r));
});

test('SEC-02 fix-server: body size cap returns 413 for declared and chunked uploads', async () => {
  await withServer(async (port) => {
    const big = JSON.stringify({ pad: 'x'.repeat(MAX_BODY_BYTES + 10) });
    assert.equal((await signedPost(port, big)).status, 413);
    assert.equal((await signedPost(port, big, { chunked: true })).status, 413);
  });
});

test('SEC-03 fix-server: signature compare is constant-time (timingSafeEqual) and rejects any length or byte difference', () => {
  assert.match(readFileSync(new URL('../src/remediate.ts', import.meta.url), 'utf8'), /timingSafeEqual/);
  const now = new Date(1_700_000_000_000);
  const ts = String(Math.floor(now.getTime() / 1000));
  const good = signBody('{}', SECRET, ts);
  assert.deepEqual(verifySignature('{}', SECRET, ts, good, now), { ok: true });
  const flipped = good.slice(0, -1) + (good.endsWith('0') ? '1' : '0');
  assert.equal(verifySignature('{}', SECRET, ts, flipped, now).ok, false);
  assert.equal(verifySignature('{}', SECRET, ts, good + '0', now).ok, false);
  assert.equal(verifySignature('{}', SECRET, ts, good.slice(0, -2), now).ok, false);
  assert.equal(verifySignature('{}', SECRET, ts, '', now).ok, false);
  assert.equal(verifySignature('{}', SECRET, ts, undefined, now).ok, false);
});

test('SEC-04 fix-server: timestamp window enforced both directions, malformed timestamps refused', () => {
  const now = new Date(1_700_000_000_000);
  const base = Math.floor(now.getTime() / 1000);
  for (const delta of [-301, 301, -86_400]) {
    const ts = String(base + delta);
    assert.equal(verifySignature('{}', SECRET, ts, signBody('{}', SECRET, ts), now, 300).ok, false, `delta ${delta}`);
  }
  for (const delta of [-299, 0, 299]) {
    const ts = String(base + delta);
    assert.equal(verifySignature('{}', SECRET, ts, signBody('{}', SECRET, ts), now, 300).ok, true, `delta ${delta}`);
  }
  for (const ts of ['abc', '-5', '1e9', '', '99999999999999']) assert.equal(verifySignature('{}', SECRET, ts, signBody('{}', SECRET, ts), now).ok, false, ts);
});

test('SEC-05 fix-server: replayed signature is rejected over a real socket', async () => {
  const key = 'GHSA-a|p|npm:x@1.0.0';
  const prep = (dir: string) => {
    const s = new StateStore(dir);
    s.state.findings[key] = { key } as never;
    s.save();
  };
  await withServer(async (port, _d, queued) => {
    const body = JSON.stringify({ schema: 'osmosecure.remediation.v1', fingerprint: `osmosecure-${key}` });
    const ts = String(Math.floor(Date.now() / 1000));
    assert.equal((await signedPost(port, body, { ts })).status, 202);
    assert.equal((await signedPost(port, body, { ts })).status, 409);
    assert.deepEqual(queued, [key]);
  }, prep);
});

test('SEC-06 fix-server: finding key is validated; prototype names and control characters are never accepted', async () => {
  assert.equal(isValidFindingKey('GHSA-a|p|npm:x@1.0.0'), true);
  for (const bad of ['', 'a\nb', 'a\u0000b', 'x'.repeat(401)]) assert.equal(isValidFindingKey(bad), false);
  await withServer(async (port, _d, queued) => {
    for (const key of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'bad\nkey', 'unknown']) {
      const body = JSON.stringify({ schema: 'osmosecure.remediation.v1', fingerprint: `osmosecure-${key}` });
      assert.equal((await signedPost(port, body)).status, 422, key);
    }
    assert.deepEqual(queued, []);
  });
});

test('SEC-07 fix-server: corrupt state yields a generic 500, not a crash or a leaked path', async () => {
  await withServer(
    async (port) => {
      const body = JSON.stringify({ schema: 'osmosecure.remediation.v1', fingerprint: 'osmosecure-k' });
      const res = await signedPost(port, body);
      assert.equal(res.status, 500);
      assert.equal(res.body, JSON.stringify({ error: 'internal error' }));
    },
    (dir) => writeFileSync(path.join(dir, 'state.json'), '{not json'),
  );
});

test('SEC-08 no shell: no source file imports exec/execSync/spawnSync or sets a shell option', () => {
  const walk = (d: string): string[] => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.ts') ? [path.join(d, e.name)] : []));
  const files = walk(new URL('../src', import.meta.url).pathname);
  assert.ok(files.length > 20);
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*'node:child_process'/g)) {
      for (const raw of m[1].split(',')) {
        const name = raw.trim().replace(/^type\s+/, '').split(/\s+/)[0];
        if (name && !raw.trim().startsWith('type ')) assert.ok(['execFile', 'spawn'].includes(name), `${f} imports ${name}`);
      }
    }
    assert.ok(!/shell\s*:\s*(true|['"`])/.test(text), `${f} enables a shell`);
    assert.ok(!/\bexecSync\b|\bspawnSync\b|\bexecFileSync\b/.test(text), `${f} uses a sync exec`);
  }
});

// ---------------------------------------------------------------- 2. feeds

test('SEC-09 ssrf: private, loopback, link-local, metadata and mapped addresses are classified private', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', 'ff02::1', '64:ff9b::7f00:1', 'not-an-ip']) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) assert.equal(isPrivateAddress(ip), false, ip);
});

test('SEC-10 ssrf: assertPublicUrl blocks schemes, credentials, internal names, literal IPs and names that resolve privately', async () => {
  for (const u of ['file:///etc/passwd', 'ftp://example.com/x', 'http://user:pw@example.com/', 'http://localhost/x', 'http://[::1]/x', 'http://127.0.0.1:8787/fix', 'http://2130706433/', 'http://169.254.169.254/latest/meta-data', 'http://intranet/x', 'http://svc.internal/x', 'not a url']) {
    await assert.rejects(() => assertPublicUrl(u, { lookup: HOSTS_OK }), /blocked|invalid|credentials/, u);
  }
  await assert.rejects(() => assertPublicUrl('https://rebind.example.com/', { lookup: async () => ['93.184.216.34', '10.0.0.7'] }), /resolves to a private/);
  await assert.doesNotReject(() => assertPublicUrl('https://example.com/feed', { lookup: HOSTS_OK }));
  await assert.doesNotReject(() => assertPublicUrl('http://127.0.0.1/x', { allowPrivate: true }));
});

const reply = (status: number, body: string, headers: Record<string, string> = {}) => new Response(body, { status, headers });

test('SEC-11 ssrf: a redirect to an internal address is refused before it is fetched; credentials do not cross origins', async () => {
  const seen: string[] = [];
  const hits: Record<string, string>[] = [];
  const fake = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    seen.push(u);
    hits.push({ ...((init?.headers as Record<string, string>) ?? {}) });
    assert.equal(init?.redirect, 'manual');
    if (u === 'https://feed.example.com/a') return reply(302, '', { location: 'http://169.254.169.254/latest/meta-data/' });
    if (u === 'https://feed.example.com/b') return reply(301, '', { location: 'https://other.example.org/x' });
    if (u === 'https://other.example.org/x') return reply(200, 'ok');
    if (u === 'https://feed.example.com/loop') return reply(302, '', { location: '/loop' });
    return reply(404, '');
  }) as typeof fetch;
  const client = new HttpClient('ua', silentLogger, undefined, fake, async () => {}, { lookup: HOSTS_OK });
  await assert.rejects(() => client.request('https://feed.example.com/a'), /blocked/);
  assert.ok(!seen.includes('http://169.254.169.254/latest/meta-data/'));
  const ok = await client.request('https://feed.example.com/b', {}, { headers: { authorization: 'Bearer tok', apikey: 'k', 'x-keep': '1' } });
  assert.equal(ok.body, 'ok');
  assert.equal(hits[hits.length - 2].authorization, 'Bearer tok'); // first hop keeps it
  const last = hits[hits.length - 1];
  assert.equal(last.authorization, undefined);
  assert.equal(last.apikey, undefined);
  assert.equal(last['x-keep'], '1');
  await assert.rejects(() => client.request('https://feed.example.com/loop'), /too many redirects/);
  await assert.rejects(() => client.request('file:///etc/passwd'), /blocked/);
  await assert.rejects(() => client.request('http://127.0.0.1:8787/'), /blocked/);
});

test('SEC-12 feeds: response size cap applies to declared and streamed bodies, and is not retried', async () => {
  let calls = 0;
  const declared = (async () => (calls++, reply(200, 'x'.repeat(100), { 'content-length': '5000000' }))) as typeof fetch;
  await assert.rejects(() => new HttpClient('ua', silentLogger, undefined, declared, async () => {}, { lookup: HOSTS_OK }).request('https://a.example.com/', {}, { maxBytes: 1000 }), /exceeds 1000 bytes/);
  assert.equal(calls, 1);
  const streamed = (async () => {
    const enc = new TextEncoder();
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(enc.encode('y'.repeat(600)));
        c.enqueue(enc.encode('y'.repeat(600)));
        c.close();
      },
    });
    return new Response(stream, { status: 200 });
  }) as typeof fetch;
  await assert.rejects(() => new HttpClient('ua', silentLogger, undefined, streamed, async () => {}, { lookup: HOSTS_OK }).request('https://a.example.com/', {}, { maxBytes: 1000 }), /exceeds 1000 bytes/);
  const small = (async () => reply(200, 'fine')) as typeof fetch;
  assert.equal((await new HttpClient('ua', silentLogger, undefined, small, async () => {}, { lookup: HOSTS_OK }).request('https://a.example.com/', {}, { maxBytes: 1000 })).body, 'fine');
});

test('SEC-13 feeds: every attempt carries an abort timeout and a hung server fails the request', async () => {
  const signals: AbortSignal[] = [];
  const hang = ((_u: string, init?: RequestInit) =>
    new Promise((_r, reject) => {
      signals.push(init?.signal as AbortSignal);
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
    })) as unknown as typeof fetch;
  const client = new HttpClient('ua', silentLogger, undefined, hang, async () => {}, { lookup: HOSTS_OK });
  const keepAlive = setInterval(() => {}, 20); // AbortSignal.timeout timers are unref'd
  try {
    await assert.rejects(() => client.request('https://slow.example.com/', {}, { timeoutMs: 20 }), /request failed/);
  } finally {
    clearInterval(keepAlive);
  }
  assert.equal(signals.length, 3);
  assert.ok(signals.every((s) => s.aborted));
});

test('SEC-14 xml: DOCTYPE and ENTITY are refused, hostile numeric entities do not throw, links keep http(s) only', () => {
  const dtd = '<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><rss><channel><item><title>&b;</title></channel></rss>';
  assert.throws(() => parseFeed(dtd, 's'), /DOCTYPE\/ENTITY/);
  assert.throws(() => parseFeed('<!entity x "y"><rss></rss>', 's'), /DOCTYPE\/ENTITY/);
  const hostile = '<rss><channel><item><title>t &#99999999999; &#x110000; &#xD800; ok</title><link>javascript:alert(1)</link></item><item><title>u</title><link>https://a.example.com/p</link></item></channel></rss>';
  const items = parseFeed(hostile, 's');
  assert.equal(items.length, 2);
  assert.match(items[0].title, /^t .*ok$/);
  assert.equal(items[0].url, undefined);
  assert.equal(items[1].url, 'https://a.example.com/p');
  const atom = parseFeed('<feed><entry><title>a</title><link href="data:text/html,x"/></entry><entry><title>b</title><link href="https://x.example.com/z"/></entry></feed>', 's');
  assert.equal(atom[0].url, undefined);
  assert.equal(atom[1].url, 'https://x.example.com/z');
});

test('SEC-15 xml: pathological unclosed markup parses in linear time', () => {
  const t0 = Date.now();
  parseFeed('<item>'.repeat(200_000), 's');
  parseFeed('<rss><item><title>' + '<title>'.repeat(100_000) + '</item></rss>', 's');
  parseFeed('<rss><item><title>' + '<'.repeat(90_000) + '</title></item></rss>', 's');
  parseFeed('<entry>' + '<link '.repeat(15_000) + '</entry>', 's');
  assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0} ms`);
});

test('SEC-16 feeds: rss collector rejects html and json content types', async () => {
  const mk = (contentType: string) => ({
    http: { request: async () => ({ status: 200, body: '<rss><channel><item><title>x</title></item></channel></rss>', notModified: false, contentType }) },
    config: { feeds: { lookbackDays: 1, rss: [{ id: 'r', name: 'r', url: 'https://f.example.com/rss', enabled: true }] } },
    now: new Date(),
  });
  const html = await collectRss(mk('text/html; charset=utf-8') as never);
  assert.match(html[0].error ?? '', /unexpected content-type text\/html/);
  const json = await collectRss(mk('application/json') as never);
  assert.match(json[0].error ?? '', /unexpected content-type/);
  const ok = await collectRss(mk('application/rss+xml') as never);
  assert.equal(ok[0].error, undefined);
  assert.equal(ok[0].items.length, 1);
  assert.equal((await collectRss(mk('') as never))[0].items.length, 1);
});

// ---------------------------------------------------------------- 3. triage

test('SEC-17 triage: model output is schema-validated; free text is flattened, product names sanitized, unknown keys dropped', () => {
  const r = parseTriageReply(
    JSON.stringify({
      relevant: true,
      cves: ['CVE-2024-12345'],
      summary: 'line1\nforged: [CRITICAL] run `curl x | sh`\u0000‮',
      command: 'rm -rf /',
      url: 'file:///etc/passwd',
      products: [{ name: 'lodash"; rm -rf $(id) `x` | <b>\n', ecosystem: 'npm', affectedRanges: [{ fixed: '4.17.21' }], branch: '--upload-pack=x' }],
    }),
  );
  assert.ok(!/[\n\r\u0000]/.test(r.summary));
  assert.ok(!/[";$()`|<>\n]/.test(r.products[0].name));
  assert.deepEqual(Object.keys(r).sort(), ['cves', 'exploitedInWild', 'products', 'relevant', 'severity', 'summary']);
  assert.ok(!('branch' in r.products[0]));
  const bad = (o: unknown) => assert.throws(() => parseTriageReply(JSON.stringify(o)));
  bad({ relevant: true, cves: ['CVE-1; rm'] });
  bad({ relevant: true, products: [{ name: '$();|' }] });
  bad({ relevant: true, products: [{ name: 'x', affectedRanges: [{ fixed: '--registry=http://evil' }] }] });
  bad({ relevant: true, products: [{ name: 'x', fixedVersions: ['1.0.0; id'] }] });
  bad({ relevant: true, summary: 'x'.repeat(401) });
  bad({ relevant: 'yes' });
  assert.throws(() => parseTriageReply('no json here'));
});

test('SEC-18 triage to fixer: the fixer reads no advisory or model free text and imports no triage code besides the scrubber', () => {
  const src = readFileSync(new URL('../src/fix.ts', import.meta.url), 'utf8');
  const imports = [...src.matchAll(/from '(\.[^']+)'/g)].map((m) => m[1]).filter((p) => p.includes('triage'));
  assert.deepEqual(imports, ['./triage/scrub.js']);
  assert.ok(!/\bf\.(title|note|url|summary|aliases)\b/.test(src));
  assert.match(src, /f\.basis !== 'deterministic'/);
});

// ---------------------------------------------------------------- 4. fixer

test('SEC-19 fixer: package manager argv is built only from validated names and versions; a leading dash never becomes a flag', () => {
  for (const pkg of ['-g', '--registry=http://evil', '--prefix=/', '-', '@scope/-x', 'a b', 'a;b', '../x', '']) {
    assert.throws(() => bumpCommand('npm', pkg, '1.0.0', 'dependencies'), /validation/, pkg);
    assert.throws(() => updateCommand('pnpm', pkg), /validation/, pkg);
  }
  for (const v of ['-1.0.0', '--force', '1.0', '^1.0.0', '1.0.0 --foo', 'latest', '1.0.0;id', '']) assert.throws(() => bumpCommand('pnpm', 'lodash', v, 'devDependencies'), /validation/, v);
  const argv = bumpCommand('npm', 'lodash', '4.17.21', 'dependencies');
  assert.deepEqual(argv.slice(0, 3), ['npm', 'install', 'lodash@4.17.21']);
  assert.ok(argv.includes('--ignore-scripts'));
  assert.ok(bumpCommand('pnpm', '@scope/pkg', '1.2.3-rc.1', 'optionalDependencies').includes('--ignore-scripts'));
  assert.equal(updateCommand('npm', 'lodash')[2], 'lodash');
});

test('SEC-20 fixer: branch names always carry the osmosecure/fix- prefix and survive hostile ids', () => {
  for (const id of ['--delete', '-D', '../../etc', 'a b;c', '$(id)', 'x\n y', '..']) {
    const b = branchFor(id, '--force', '../../..');
    assert.ok(b.startsWith('osmosecure/fix-'), b);
    assert.ok(!b.includes('..') && !/[\s;$()`\\~^:?*[]/.test(b), b);
    execFileSync('git', ['check-ref-format', '--branch', b]);
  }
  assert.ok(!slug('--flag').startsWith('-'));
});

test('SEC-21 fixer: publish refuses a remote that could be read as a git option', async () => {
  const dir = tmp('pub');
  const runs = path.join(dir, 'fix', 'runs');
  mkdirSync(runs, { recursive: true });
  writeFileSync(path.join(runs, 'r1.json'), JSON.stringify({ id: 'r1', status: 'approved', commit: 'abc', branch: 'osmosecure/fix-x', worktree: dir, repoRoot: dir }));
  for (const remote of ['--force', '--mirror', '-f', '--delete']) {
    const config = parseConfig({ dataDir: dir, fix: { publish: { enabled: true, remote } } }, dir);
    await assert.rejects(() => publishFix({ config, log: silentLogger }, 'r1'), /invalid remote name/, remote);
  }
});

test('SEC-22 fixer: a manifest directory that is a symlink out of the worktree is refused before any package manager runs', async () => {
  const base = tmp('link');
  const repo = path.join(base, 'repo');
  mkdirSync(repo);
  const noGlobal = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };
  const vcs = (...a: string[]) => execFileSync('git', a, { cwd: repo, encoding: 'utf8', env: noGlobal }).trim();
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.15' } } });
  writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ name: 'd', scripts: { test: 'true' }, dependencies: { lodash: '^4.17.15' } }));
  writeFileSync(path.join(repo, 'package-lock.json'), lock);
  symlinkSync('../outside', path.join(repo, 'link'));
  vcs('init', '-q', '-b', 'main');
  vcs('config', 'user.name', 'T');
  vcs('config', 'user.email', 't@example.test');
  vcs('config', 'commit.gpgsign', 'false');
  vcs('add', '.');
  vcs('commit', '-q', '-m', 'init');
  const dataDir = path.join(base, 'data');
  const wtRoot = path.join(base, 'wt');
  const outside = path.join(wtRoot, 'outside');
  mkdirSync(outside, { recursive: true });
  writeFileSync(path.join(outside, 'package.json'), JSON.stringify({ name: 'evil', dependencies: { lodash: '^4.17.15' } }));
  writeFileSync(path.join(outside, 'package-lock.json'), lock);
  const config = parseConfig({ dataDir, projects: [{ id: 'demo', root: repo }], fix: { worktreeRoot: wtRoot } }, base);
  const key = 'k1';
  const store = new StateStore(dataDir);
  store.state.findings[key] = {
    key, advisoryId: 'GHSA-xxxx-yyyy-zzzz', aliases: [], cves: [], title: 't', severity: 'high', source: 'osv',
    component: { ecosystem: 'npm', name: 'lodash', version: '4.17.15', origin: 'link/package-lock.json', project: 'demo', kind: 'package' },
    fixedVersion: '4.17.21', basis: 'deterministic', verdict: 'affected', kev: false, score: 70, tier: 'alert', firstSeen: 'x', lastSeen: 'x',
  } as never;
  store.save();
  const ran: string[] = [];
  const exec: Exec = (cmd, args, o) =>
    cmd === 'git'
      ? defaultExec(cmd, args, { ...o, env: { ...o.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' } })
      : (ran.push(cmd), Promise.resolve({ code: 0, stdout: '', stderr: '', timedOut: false }));
  const r = await startFix({ config, log: silentLogger, exec }, { findingKey: key });
  assert.equal(r.status, 'failed');
  assert.match(r.reason ?? '', /outside the worktree/);
  assert.deepEqual(ran, []);
});

// ---------------------------------------------------------------- 5. secrets

test('SEC-23 secrets: webhook, token and password style env values are scrubbed from any text that is logged or reported', () => {
  const env = { SLACK_WEBHOOK_URL: 'https://hooks.example.test/services/T000/B000/abcdefghijklmnop', REGISTRY_PASS: 'registry-pass-value-123', OSMOSECURE_HOOK_SECRET: SECRET, PLAIN: 'visible-value-123456' };
  const out = scrubSecrets(`fail ${env.SLACK_WEBHOOK_URL} ${env.REGISTRY_PASS} ${SECRET} ${env.PLAIN}`, env);
  assert.ok(!out.includes('abcdefghijklmnop') && !out.includes('registry-pass-value-123') && !out.includes(SECRET));
  assert.ok(out.includes('visible-value-123456'));
});

test('SEC-24 secrets: notifier errors never echo the bot token or webhook URL', async () => {
  const token = '123456789:AAFakeTokenValueFakeTokenValueFake_12345';
  const hook = 'https://hooks.slack.test/services/T000/B000/SECRETPATHPART12345';
  const logs: string[] = [];
  const log: Logger = { info() {}, error() {}, warn: (m, e) => void logs.push(`${m} ${JSON.stringify(e ?? {})}`) };
  const boom = (async (url: string | URL | Request) => {
    throw new TypeError(`Failed to parse URL from ${String(url)}`);
  }) as typeof fetch;
  const config = parseConfig({ notify: { notifiers: [{ type: 'telegram' }, { type: 'slack' }] } }, tmp('n'));
  const env = { TELEGRAM_BOT_TOKEN: token, TELEGRAM_CHAT_ID: '42', SLACK_WEBHOOK_URL: hook };
  for (const n of createNotifiers(config, env, boom)) assert.equal(await n.send('hi', log), false);
  const all = logs.join('\n');
  assert.equal(logs.length, 2);
  assert.ok(!all.includes(token) && !all.includes('AAFakeToken') && !all.includes('SECRETPATHPART'), all);
});

test('SEC-25 secrets: the fix-server never echoes why a request was refused or the secret', async () => {
  await withServer(async (port) => {
    const body = JSON.stringify({ schema: 'osmosecure.remediation.v1', fingerprint: 'osmosecure-k' });
    const res = await signedPost(port, body, { secret: 'a-different-secret-entirely-0000' });
    assert.equal(res.status, 401);
    assert.equal(res.body, JSON.stringify({ error: 'unauthorized' }));
  });
  const r = handleFixRequest({ method: 'POST', url: '/fix', body: '{}', headers: {} }, { secret: SECRET, windowSeconds: 300, hasFinding: () => false, enqueue: () => true });
  assert.ok(!JSON.stringify(r).includes(SECRET));
});
