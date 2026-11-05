import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseConfig, type Config } from '../src/config.js';
import { HttpClient } from '../src/http.js';
import { silentLogger } from '../src/lib/log.js';
import { runAudit } from '../src/run.js';
import { StateStore } from '../src/state.js';
import { ClaudeCliTriageClient, parseCliOutput, scrubbedEnv, type SpawnFn } from '../src/triage/claude-cli.js';
import { AnthropicTriageClient, createTriageClient, registerTriageBackend, triageItem } from '../src/triage/llm.js';
import { TRIAGE_SYSTEM_PROMPT } from '../src/triage/prompt.js';
import type { FeedItem } from '../src/types.js';

const fx = (n: string) => readFileSync(fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url)), 'utf8');
const config = parseConfig({}, process.cwd());

interface Call { cmd: string; args: string[]; cwd?: string; env?: NodeJS.ProcessEnv; stdin: string; cwdExistedAtSpawn: boolean }

function stubSpawn(reply: (call: Call) => { stdout?: string; code?: number; hang?: boolean }, calls: Call[] = []): SpawnFn {
  return (cmd, args, opts) => {
    const child = new EventEmitter() as EventEmitter & { stdin: PassThrough; stdout: PassThrough; stderr: PassThrough; kill: (s?: string) => boolean };
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let killed = false;
    child.kill = () => ((killed = true), true);
    let stdin = '';
    child.stdin.on('data', (d) => (stdin += d.toString()));
    child.stdin.on('end', () => {
      const call: Call = { cmd, args, cwd: opts.cwd as string, env: opts.env, stdin, cwdExistedAtSpawn: existsSync(String(opts.cwd)) };
      calls.push(call);
      const r = reply(call);
      if (r.hang) return;
      setImmediate(() => {
        if (killed) return;
        child.stdout.end(r.stdout ?? '');
        child.emit('close', r.code ?? 0);
      });
    });
    return child as never;
  };
}

const ok = (result: string) => ({ stdout: JSON.stringify({ type: 'result', subtype: 'success', is_error: false, result }) });
const item: FeedItem = { source: 'rss:php-news', id: 'php-8.3.8', title: 'PHP 8.3.8 security release', text: fx('php-disclosure.txt'), cves: [], productHints: [] };

test('claude cli backend: args, stdin, scrubbed env, temp cwd, validated reply', async () => {
  const calls: Call[] = [];
  const client = new ClaudeCliTriageClient({
    model: 'sonnet', timeoutMs: 5000, concurrency: 1,
    env: { PATH: '/bin', HOME: '/home/x', ANTHROPIC_API_KEY: 'sk-secret', TELEGRAM_BOT_TOKEN: 't', OSMOSECURE_HOOK_SECRET: 'm', CLAUDE_CODE_OAUTH_TOKEN: 'oat' },
    spawnFn: stubSpawn(() => ok(fx('php-triage-reply.json')), calls),
  });
  const t = await triageItem(client, item, 6000);
  assert.equal(t.relevant, true);
  const c = calls[0];
  assert.equal(c.cmd, 'claude');
  assert.ok(c.args.includes('-p'));
  assert.equal(c.args[c.args.indexOf('--output-format') + 1], 'json');
  assert.equal(c.args[c.args.indexOf('--tools') + 1], '', 'all tools disabled');
  assert.equal(c.args[c.args.indexOf('--model') + 1], 'sonnet');
  assert.equal(c.args[c.args.indexOf('--system-prompt') + 1], TRIAGE_SYSTEM_PROMPT);
  assert.match(c.stdin, /<disclosure>/);
  assert.ok(!c.args.some((a) => a.includes('8.3.8')), 'untrusted text only on stdin');
  assert.deepEqual(Object.keys(c.env ?? {}).filter((k) => /KEY|TOKEN|SECRET/.test(k)), ['CLAUDE_CODE_OAUTH_TOKEN']);
  assert.equal(c.env?.ANTHROPIC_API_KEY, undefined);
  assert.ok(c.cwd?.includes('osmosecure-triage-') && c.cwdExistedAtSpawn);
  assert.ok(!existsSync(c.cwd!), 'temp cwd removed afterwards');
});

test('claude cli backend: failures surface (exit code, error result, bad JSON, timeout)', async () => {
  const mk = (r: ReturnType<typeof ok> | { code: number } | { hang: true }, timeoutMs = 5000) =>
    new ClaudeCliTriageClient({ model: 'sonnet', timeoutMs, concurrency: 1, env: {}, spawnFn: stubSpawn(() => r) });
  await assert.rejects(mk({ code: 1 }).complete('s', 'u'), /exit 1/);
  await assert.rejects(mk({ stdout: 'not json' } as never).complete('s', 'u'), /not JSON/);
  await assert.rejects(mk({ stdout: JSON.stringify({ is_error: true, subtype: 'error_during_execution' }) } as never).complete('s', 'u'), /error result/);
  await assert.rejects(mk({ hang: true }, 30).complete('s', 'u'), /timed out/);
  // hostile reply still fails the strict schema
  await assert.rejects(triageItem(mk(ok('{"relevant":"yes"}')), item, 6000));
});

test('claude cli backend: concurrency is capped', async () => {
  let active = 0;
  let peak = 0;
  const spawnFn: SpawnFn = (...a) => {
    const base = stubSpawn(() => (active++, (peak = Math.max(peak, active)), ok('{}')))(...a);
    base.on('close', () => active--);
    return base;
  };
  for (const [requested, expected] of [[1, 1], [2, 2], [9, 2]] as const) {
    peak = 0;
    const c = new ClaudeCliTriageClient({ model: 'm', timeoutMs: 5000, concurrency: requested, env: {}, spawnFn });
    await Promise.all(Array.from({ length: 6 }, () => c.complete('s', 'u')));
    assert.ok(peak <= expected, `peak ${peak} <= ${expected}`);
  }
});

test('parseCliOutput and scrubbedEnv', () => {
  assert.equal(parseCliOutput(JSON.stringify([{ type: 'system' }, { type: 'result', result: 'hi' }])), 'hi');
  assert.throws(() => parseCliOutput(JSON.stringify({ result: '' })));
  assert.equal(scrubbedEnv({ PATH: '/b', FOO: 'x' }).FOO, undefined);
});

test('backend selection via TRIAGE_BACKEND, config and module', async () => {
  assert.ok((await createTriageClient(config, {})) instanceof ClaudeCliTriageClient, 'default is claude-cli, no key needed');
  assert.equal(await createTriageClient(config, { TRIAGE_BACKEND: 'anthropic-api' }), null);
  assert.ok((await createTriageClient(config, { TRIAGE_BACKEND: 'anthropic-api', ANTHROPIC_API_KEY: 'k', ANTHROPIC_MODEL: 'claude-sonnet-5-5' })) instanceof AnthropicTriageClient);
  await assert.rejects(createTriageClient(config, { TRIAGE_BACKEND: 'bogus' }), /unknown triage backend/);

  const dir = mkdtempSync(path.join(tmpdir(), 'osmo-backend-'));
  writeFileSync(path.join(dir, 'b.mjs'), "export default () => ({ complete: async () => '{\"relevant\":false}' });\n");
  const custom = await createTriageClient({ ...config, configDir: dir, triage: { ...config.triage, backend: 'module:./b.mjs' } }, {});
  assert.equal(await custom!.complete('s', 'u'), '{"relevant":false}');
  // A module backend is never loadable from the environment (an untrusted .env must not load code).
  await assert.rejects(createTriageClient({ ...config, configDir: dir }, { TRIAGE_BACKEND: 'module:./b.mjs' }), /cannot load a module from the environment/);
  await assert.rejects(createTriageClient({ ...config, configDir: dir, triage: { ...config.triage, backend: 'module:./b.mjs' } }, { TRIAGE_BACKEND: ' module:./b.mjs' }), /cannot load a module from the environment/);

  registerTriageBackend('fake', () => ({ complete: async () => 'x' }));
  assert.equal(await (await createTriageClient(config, { TRIAGE_BACKEND: 'fake' }))!.complete('s', 'u'), 'x');
});


test('baseline: records findings as notified, sends nothing, marks lastRun', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'sa-proj-'));
  writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/devonly': { version: '1.0.0', dev: true } } }));
  const dataDir = mkdtempSync(path.join(tmpdir(), 'sa-data-'));
  mkdirSync(dataDir, { recursive: true });
  process.env.OSMOSECURE_DATA_DIR = dataDir;
  process.env.TELEGRAM_BOT_TOKEN = 'test-token';
  process.env.TELEGRAM_CHAT_ID = '1';
  delete process.env.OSMOSECURE_HOOK_SECRET;
  const cfg: Config = {
    ...config,
    projects: [{ id: 'demo', root, target: 'app', pathTargets: {}, maxDepth: 2, skipDirs: [], optional: false }],
    notify: { ...config.notify, notifiers: [{ type: 'telegram', tokenEnv: 'TELEGRAM_BOT_TOKEN', chatIdEnv: 'TELEGRAM_CHAT_ID' }] },
    hosts: [], localRuntimes: { includeNode: false }, scan: { ...config.scan, prefer: 'api' },
  };
  assert.equal(config.scan.includeDevDependencies, false, 'dev dependencies excluded by default');
  const queried: string[] = [];
  let telegram = 0;
  const net: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.includes('api.telegram.org')) { telegram++; return new Response('{"ok":true}'); }
    if (url.endsWith('/v1/querybatch')) {
      queried.push(String(init?.body));
      return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-test' }] }] }));
    }
    if (url.includes('/v1/vulns/GHSA-test')) {
      return new Response(JSON.stringify({ id: 'GHSA-test', aliases: ['CVE-2099-9'], summary: 'x', database_specific: { severity: 'HIGH' },
        affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }));
    }
    if (url.includes('api.first.org')) return new Response(JSON.stringify({ data: [] }));
    throw new Error(`unexpected network call ${url}`);
  };
  const origFetch = globalThis.fetch;
  globalThis.fetch = net;
  try {
    const mk = () => new HttpClient('ua', silentLogger, undefined, net, async () => {});
    const base = { due: false, groups: ['inventory-scan'], dryRun: false, remediateLive: false, noLlm: true, deadlineMs: 60_000 };
    const first = await runAudit(cfg, { ...base, baseline: true }, silentLogger, { http: mk() });
    assert.equal(telegram, 0);
    assert.equal(first.notified, 0);
    assert.equal(first.baseline?.recorded, 1);
    assert.equal(first.baseline?.byTier.alert, 1);
    assert.equal(first.remediation.posted, 0);
    assert.ok(!queried.join('').includes('devonly'), 'dev dependency not scanned');
    const store = new StateStore(dataDir);
    assert.equal(Object.keys(store.state.notified).length, 1);
    assert.equal(Object.keys(store.state.remediated).length, 0);
    assert.ok(store.state.lastRun['inventory-scan']);
    // a normal run afterwards stays silent for the baselined finding
    const second = await runAudit(cfg, base, silentLogger, { http: mk() });
    assert.equal(second.findingsNew, 0);
    assert.equal(telegram, 0, 'first live run does not flood Telegram');
  } finally {
    globalThis.fetch = origFetch;
    delete process.env.OSMOSECURE_DATA_DIR;
    delete process.env.TELEGRAM_BOT_TOKEN;
    delete process.env.TELEGRAM_CHAT_ID;
  }
});
