import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { parseConfig } from '../src/config.js';
import { runSetup, type SetupOptions } from '../src/commands/setup.js';

const CODE = 'osc_00112233445566778899aabbccddeeff';
const tmp = () => realpathSync(mkdtempSync(path.join(tmpdir(), 'osmosecure-setup-')));

let reply: { status: number; body: unknown } = { status: 200, body: {} };
let hits = 0;
let lastBody = '';
const stub = http.createServer((req, res) => {
  hits++;
  let data = '';
  req.on('data', (c) => (data += c));
  req.on('end', () => {
    lastBody = data;
    res.writeHead(reply.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(reply.body));
  });
});
await new Promise<void>((r) => stub.listen(0, '127.0.0.1', r));
const SERVER = `http://127.0.0.1:${(stub.address() as AddressInfo).port}`;
after(() => stub.close());

const cfg = (accessLevel: number, notifiers: unknown[] = [{ type: 'stdout' }], extra: Record<string, unknown> = {}) => ({
  config: { schemaVersion: 1, projects: [{ id: 'web', root: '.' }], notify: { notifiers }, accessLevel, ...extra },
});

async function run(over: Partial<SetupOptions> = {}, dir = tmp()) {
  const lines: string[] = [];
  const io = { out: (l: string) => lines.push(l), err: (l: string) => lines.push(l) };
  const code = await runSetup({ code: CODE, server: SERVER, dir, force: false, allowPropose: false, ...over }, io);
  return { code, dir, output: lines.join('\n'), file: path.join(dir, 'osmosecure.config.json') };
}

test('success writes a config with no secrets and prints env var names only', async () => {
  reply = { status: 200, body: cfg(2, [{ type: 'stdout' }, { type: 'slack' }, { type: 'telegram' }]) };
  const r = await run();
  assert.equal(r.code, 0, r.output);
  const raw = readFileSync(r.file, 'utf8');
  const parsed = JSON.parse(raw);
  assert.equal(parsed.accessLevel, 2);
  assert.deepEqual(parsed.projects, [{ id: 'web', root: '.' }]);
  assert.ok(!raw.includes(CODE));
  assert.ok(!/key|secret|password/i.test(raw));
  assert.equal(JSON.parse(lastBody).code, CODE);
  for (const n of ['SLACK_WEBHOOK_URL', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID']) assert.ok(r.output.includes(n));
  assert.ok(!r.output.includes(CODE));
  // the loader accepts the written file
  const loaded = parseConfig(parsed, r.dir);
  assert.equal(loaded.projects[0].id, 'web');
});

test('level 1 writes no alert settings and needs no env vars', async () => {
  reply = { status: 200, body: cfg(1, [{ type: 'stdout' }, { type: 'slack' }]) };
  const r = await run();
  assert.equal(r.code, 0, r.output);
  assert.deepEqual(JSON.parse(readFileSync(r.file, 'utf8')).notify.notifiers, [{ type: 'stdout' }]);
  assert.ok(!r.output.includes('SLACK_WEBHOOK_URL'));
});

test('refuses a non-https remote server before any request', async () => {
  const before = hits;
  const r = await run({ server: 'http://example.com' });
  assert.equal(r.code, 1);
  assert.match(r.output, /https/);
  assert.equal(hits, before);
  assert.ok(!existsSync(r.file));
  assert.ok(!r.output.includes(CODE));
});

test('refuses a response containing apiKey, without echoing it', async () => {
  reply = { status: 200, body: cfg(2, [{ type: 'stdout' }], { apiKey: 'sk-live-SUPERSECRETVALUE123456' }) };
  const r = await run();
  assert.equal(r.code, 1);
  assert.match(r.output, /secret-looking/);
  assert.ok(!r.output.includes('SUPERSECRETVALUE'));
  assert.ok(!existsSync(r.file));
});

test('refuses a secret-looking value under an innocent key', async () => {
  reply = { status: 200, body: cfg(2, [{ type: 'stdout' }], { note: 'https://hooks.slack.com/services/T000/B000/XXXX' }) };
  const r = await run();
  assert.equal(r.code, 1);
  assert.ok(!r.output.includes('hooks.slack.com'));
  assert.ok(!existsSync(r.file));
});

test('refuses to overwrite an existing config without --force, allows it with --force', async () => {
  reply = { status: 200, body: cfg(2) };
  const dir = tmp();
  writeFileSync(path.join(dir, 'osmosecure.config.json'), '{"keep":true}\n');
  const before = hits;
  const r = await run({}, dir);
  assert.equal(r.code, 1);
  assert.equal(hits, before, 'the code must not be spent when the write would be refused');
  assert.equal(readFileSync(r.file, 'utf8'), '{"keep":true}\n');
  const forced = await run({ force: true }, dir);
  assert.equal(forced.code, 0, forced.output);
  assert.equal(JSON.parse(readFileSync(r.file, 'utf8')).accessLevel, 2);
});

test('never prints the code or the response body, on success or failure', async () => {
  reply = { status: 400, body: { error: 'invalid_or_expired_code', detail: 'BODYMARKER' } };
  const bad = await run();
  assert.equal(bad.code, 1);
  assert.ok(!bad.output.includes(CODE) && !bad.output.includes('BODYMARKER'));
  reply = { status: 200, body: cfg(2, [{ type: 'stdout' }], { extraMarker: 'BODYMARKER' }) };
  const odd = await run();
  assert.equal(odd.code, 1);
  assert.ok(!odd.output.includes(CODE) && !odd.output.includes('BODYMARKER'));
  reply = { status: 200, body: cfg(2) };
  const ok = await run();
  assert.ok(!ok.output.includes(CODE));
});

test('access level 4 and 0 are refused', async () => {
  for (const level of [4, 0, 9]) {
    reply = { status: 200, body: cfg(level) };
    const r = await run();
    assert.equal(r.code, 1);
    assert.match(r.output, /not supported/);
    assert.ok(!existsSync(r.file));
  }
});

test('level 3 needs --allow-propose and records it', async () => {
  reply = { status: 200, body: cfg(3, [{ type: 'stdout' }, { type: 'telegram' }]) };
  const denied = await run();
  assert.equal(denied.code, 1);
  assert.match(denied.output, /--allow-propose/);
  assert.ok(!existsSync(denied.file));
  const ok = await run({ allowPropose: true });
  assert.equal(ok.code, 0, ok.output);
  const parsed = JSON.parse(readFileSync(ok.file, 'utf8'));
  assert.equal(parsed.accessLevel, 3);
  assert.equal(parsed.allowPropose, true);
});

test('an openPullRequests field from an older server is accepted and never written', async () => {
  reply = { status: 200, body: cfg(3, [{ type: 'stdout' }], { openPullRequests: true }) };
  const ok = await run({ allowPropose: true });
  assert.equal(ok.code, 0, ok.output);
  assert.equal(JSON.parse(readFileSync(ok.file, 'utf8')).openPullRequests, undefined);
});

test('prints missing .gitignore lines but never edits the file', async () => {
  reply = { status: 200, body: cfg(2) };
  const dir = tmp();
  writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n');
  const r = await run({}, dir);
  assert.equal(r.code, 0, r.output);
  assert.match(r.output, /\.osmosecure\//);
  assert.match(r.output, /\.env/);
  assert.equal(readFileSync(path.join(dir, '.gitignore'), 'utf8'), 'node_modules/\n');
  const dir2 = tmp();
  writeFileSync(path.join(dir2, '.gitignore'), '.osmosecure/\n.env\n');
  const r2 = await run({}, dir2);
  assert.ok(!r2.output.includes('missing'));
});

test('falls back to OSMOSECURE_SERVER when --server is absent', async () => {
  reply = { status: 200, body: cfg(1) };
  process.env.OSMOSECURE_SERVER = SERVER;
  try {
    const r = await run({ server: undefined });
    assert.equal(r.code, 0, r.output);
  } finally {
    delete process.env.OSMOSECURE_SERVER;
  }
});
