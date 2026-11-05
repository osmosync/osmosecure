import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { assertFixerAllowed, parseConfig } from '../src/config.js';
import { silentLogger } from '../src/lib/log.js';
import { createNotifiers, sendAll } from '../src/notify/index.js';

function recorder() {
  const calls: { url: string; body: string }[] = [];
  const f: typeof fetch = async (url, init) => {
    calls.push({ url: String(url), body: String(init?.body) });
    return new Response('ok');
  };
  return { calls, f };
}

test('telegram notifier reads the env var names from the config', async () => {
  const cfg = parseConfig({ notify: { notifiers: [{ type: 'telegram', tokenEnv: 'MY_TOK', chatIdEnv: 'MY_CHAT' }] } }, '.');
  const { calls, f } = recorder();
  // The default names must be ignored when custom names are configured.
  const n = createNotifiers(cfg, { TELEGRAM_BOT_TOKEN: 'wrong', TELEGRAM_CHAT_ID: 'wrong', MY_TOK: 'tok123', MY_CHAT: '42' }, f);
  assert.equal(await sendAll(n, 'hi', silentLogger), true);
  assert.ok(calls[0].url.includes('/bottok123/'));
  assert.equal(JSON.parse(calls[0].body).chat_id, '42');
  const missing = createNotifiers(cfg, { TELEGRAM_BOT_TOKEN: 'x', TELEGRAM_CHAT_ID: 'y' }, f);
  assert.equal(await sendAll(missing, 'hi', silentLogger), false);
});

test('telegram defaults still use the standard names', async () => {
  const cfg = parseConfig({ notify: { notifiers: [{ type: 'telegram' }] } }, '.');
  const { calls, f } = recorder();
  assert.equal(await sendAll(createNotifiers(cfg, { TELEGRAM_BOT_TOKEN: 't', TELEGRAM_CHAT_ID: 'c' }, f), 'hi', silentLogger), true);
  assert.equal(calls.length, 1);
});

test('slack notifier uses urlEnv from the config', async () => {
  const cfg = parseConfig({ notify: { notifiers: [{ type: 'slack', urlEnv: 'MY_SLACK' }] } }, '.');
  const { calls, f } = recorder();
  const n = createNotifiers(cfg, { SLACK_WEBHOOK_URL: 'https://wrong.example.test/x', MY_SLACK: 'https://right.example.test/x' }, f);
  assert.equal(await sendAll(n, 'hi', silentLogger), true);
  assert.deepEqual(calls.map((c) => c.url), ['https://right.example.test/x']);
});

test('access level 1 sends no alerts', async () => {
  const cfg = parseConfig(
    { accessLevel: 1, notify: { notifiers: [{ type: 'stdout' }, { type: 'telegram' }, { type: 'slack' }, { type: 'webhook' }] } },
    '.',
  );
  const { calls, f } = recorder();
  const env = { TELEGRAM_BOT_TOKEN: 't', TELEGRAM_CHAT_ID: 'c', SLACK_WEBHOOK_URL: 'https://a.example.test/s', OSMOSECURE_WEBHOOK_URL: 'https://a.example.test/w' };
  const n = createNotifiers(cfg, env, f);
  assert.deepEqual(n.map((x) => x.name), ['stdout']);
  await sendAll(n, 'hi', silentLogger);
  assert.equal(calls.length, 0);
});

test('access level 2 still alerts', async () => {
  const cfg = parseConfig({ accessLevel: 2, notify: { notifiers: [{ type: 'slack' }] } }, '.');
  const { calls, f } = recorder();
  await sendAll(createNotifiers(cfg, { SLACK_WEBHOOK_URL: 'https://a.example.test/s' }, f), 'hi', silentLogger);
  assert.equal(calls.length, 1);
});

test('access level 4 and out-of-range values are refused', () => {
  assert.throws(() => parseConfig({ accessLevel: 4 }, '.'), /not supported/);
  assert.throws(() => parseConfig({ accessLevel: 9 }, '.'));
  assert.throws(() => parseConfig({ accessLevel: 0 }, '.'));
});

test('fixer commands: level 3 needs allowPropose, lower levels refused, absent level keeps legacy behaviour', () => {
  assert.throws(() => assertFixerAllowed(parseConfig({ accessLevel: 1 }, '.')), /level 3 is required/);
  assert.throws(() => assertFixerAllowed(parseConfig({ accessLevel: 2 }, '.')), /level 3 is required/);
  assert.throws(() => assertFixerAllowed(parseConfig({ accessLevel: 3 }, '.')), /allowPropose/);
  assert.throws(() => assertFixerAllowed(parseConfig({ accessLevel: 3, allowPropose: false }, '.')), /allowPropose/);
  assert.doesNotThrow(() => assertFixerAllowed(parseConfig({ accessLevel: 3, allowPropose: true }, '.')));
  assert.doesNotThrow(() => assertFixerAllowed(parseConfig({}, '.')));
});

test('the cli refuses fix at level 3 without allowPropose and any config at level 4', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'osec-lvl-'));
  const cli = path.resolve(import.meta.dirname, '../src/cli.ts');
  const run = (cfg: object, args: string[]) => {
    const file = path.join(dir, 'osmosecure.config.json');
    writeFileSync(file, JSON.stringify(cfg));
    return spawnSync(process.execPath, ['--import', import.meta.resolve('tsx'), cli, ...args, '--config', file], { encoding: 'utf8', cwd: dir, timeout: 30_000 });
  };
  const a = run({ schemaVersion: 1, accessLevel: 3 }, ['fix', '--list']);
  assert.notEqual(a.status, 0);
  assert.match(a.stderr, /allowPropose/);
  const b = run({ schemaVersion: 1, accessLevel: 4 }, ['status']);
  assert.notEqual(b.status, 0);
  assert.match(b.stderr, /not supported/);
  const c = run({ schemaVersion: 1, accessLevel: 3, allowPropose: true }, ['fix', '--list']);
  assert.equal(c.status, 0, c.stderr);
});
