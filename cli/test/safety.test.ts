import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { initProject } from '../src/commands/init.js';
import { acquireLock } from '../src/commands/lock.js';
import { parseConfig, loadConfig } from '../src/config.js';
import { loadInventoryFile } from '../src/inventory/file.js';
import { createNotifiers, isAllowedHookUrl, sendAll } from '../src/notify/index.js';
import { silentLogger } from '../src/lib/log.js';
import { buildTriageUserMessage } from '../src/triage/prompt.js';
import { scrubSecrets } from '../src/triage/scrub.js';

// Fake credentials assembled at runtime so no scanner mistakes this file for a leak.
const fake = {
  aws: ['AKIA', 'ABCDEFGHIJKLMNOP'].join(''),
  gh: ['ghp', '_', 'a'.repeat(36)].join(''),
  slack: ['xoxb', '-', '1234567890', '-', 'abcdefghij'].join(''),
  anth: ['sk-ant', '-', 'x'.repeat(30)].join(''),
};

test('secret scrubbing removes token shapes and env secret values before a model call', () => {
  const text = `leaked ${fake.aws} and ${fake.gh} and ${fake.slack} ${fake.anth}\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\npassword=hunter2hunter2`;
  const out = scrubSecrets(text, {});
  for (const v of Object.values(fake)) assert.ok(!out.includes(v));
  assert.ok(!out.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(!out.includes('hunter2hunter2'));
  const envOut = scrubSecrets('value is zzzz-env-secret-value-1234', { SOME_API_TOKEN: 'zzzz-env-secret-value-1234' });
  assert.ok(!envOut.includes('zzzz-env-secret'));
  const msg = buildTriageUserMessage('t', `body ${fake.gh}`, 'rss', 6000);
  assert.ok(!msg.includes(fake.gh));
  assert.ok(msg.includes('<disclosure>'));
});

test('notifier urls must be https or loopback http', () => {
  assert.equal(isAllowedHookUrl('https://hooks.example.test/x'), true);
  assert.equal(isAllowedHookUrl('http://localhost:9000/x'), true);
  assert.equal(isAllowedHookUrl('http://hooks.example.test/x'), false);
  assert.equal(isAllowedHookUrl('file:///etc/passwd'), false);
  assert.equal(isAllowedHookUrl('nonsense'), false);
});

test('webhook, slack and stdout notifiers; failure of one is reported', async () => {
  const cfg = parseConfig({ notify: { notifiers: [{ type: 'stdout' }, { type: 'webhook' }, { type: 'slack', urlEnv: 'S' }] } }, '.');
  const calls: { url: string; body: string }[] = [];
  const fake$: typeof fetch = async (url, init) => {
    calls.push({ url: String(url), body: String(init?.body) });
    return new Response('ok');
  };
  const env = { OSMOSECURE_WEBHOOK_URL: 'https://a.example.test/h', S: 'https://b.example.test/s' };
  const notifiers = createNotifiers(cfg, env, fake$);
  const lines: string[] = [];
  const stdout = notifiers.find((n) => n.name === 'stdout')!;
  assert.equal(await stdout.send('x', silentLogger), true);
  void lines;
  assert.equal(await sendAll(notifiers.slice(1), 'hello', silentLogger), true);
  assert.deepEqual(calls.map((c) => c.url), ['https://a.example.test/h', 'https://b.example.test/s']);
  assert.equal(JSON.parse(calls[0].body).text, 'hello');
  assert.equal(await sendAll(createNotifiers(cfg, {}, fake$).slice(1), 'hello', silentLogger), false);
});

test('config: defaults merge, user cadence overrides, relative paths resolve against the config dir', () => {
  const cfg = parseConfig({ sourceGroups: { kev: { everyMinutes: 15, sources: ['kev'] } }, projects: [{ id: 'a', root: 'src' }] }, '/cfg');
  assert.equal(cfg.sourceGroups.kev.everyMinutes, 15);
  assert.equal(cfg.sourceGroups.advisories.everyMinutes, 360);
  assert.equal(cfg.configDir, '/cfg');
  assert.equal(cfg.remediation.dryRun, true);
  assert.equal(cfg.autoFix.neverPushOrDeploy, true);
  assert.throws(() => parseConfig({ autoFix: { neverPushOrDeploy: false } }, '.'));
});

test('init writes a config that loads, and does not overwrite', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'osmo-init-'));
  assert.equal(initProject(dir).length, 2);
  assert.equal(initProject(dir).length, 0);
  const cfg = loadConfig(path.join(dir, 'osmosecure.config.json'));
  assert.equal(cfg.projects[0].id, 'my-app');
});

test('inventory file in skill format becomes host runtimes, images and packages', () => {
  const comps = loadInventoryFile(JSON.stringify({
    schema_version: 1, generated_at: '2026-10-22T00:00:00Z', owner: 'acme',
    assets: [
      { id: 'host:php', kind: 'host_runtime', name: 'php8.2-fpm', version: '8.2.19', distro: 'debian', location: 'host a', detected_by: 'dpkg' },
      { id: 'img:x', kind: 'container_image', name: 'Registry.test/Api', version: '1.0', location: 'compose', detected_by: 'x' },
      { id: 'npm:y', kind: 'lockfile_package', name: 'Lodash', version: '4.17.20', ecosystem: 'npm', location: 'package-lock.json', detected_by: 'x' },
    ],
  }));
  assert.deepEqual(comps.map((c) => `${c.kind}:${c.name}`), ['runtime:php', 'image:registry.test/api', 'package:lodash']);
  assert.equal(comps[0].distroPackaged, true);
  assert.equal(comps[0].project, 'inventory:acme');
});

test('run lock admits one holder and recovers from a stale file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'osmo-lock-'));
  const release = acquireLock(dir);
  assert.ok(release);
  assert.equal(acquireLock(dir), null);
  release!();
  writeFileSync(path.join(dir, 'run.lock'), '999999999');
  const again = acquireLock(dir);
  assert.ok(again);
  again!();
});
