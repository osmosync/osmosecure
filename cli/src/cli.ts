#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { initProject } from './commands/init.js';
import { runSetup } from './commands/setup.js';
import { acquireLock } from './commands/lock.js';
import { assertFixerAllowed, loadConfig, resolveDataDir, type Config } from './config.js';
import { createLogger } from './lib/log.js';
import { createNotifiers, sendAll } from './notify/index.js';
import { buildRequest, decide, hookReady, postRequest } from './remediate.js';
import { approveFix, discardFix, FixRefusal, listRuns, publishFix, renderReport, startFix } from './fix.js';
import { assertLoopbackHost, startFixServer } from './fix-server.js';
import { runAudit, type RunOptions } from './run.js';
import { StateStore } from './state.js';
import { buildInventory } from './inventory/index.js';
import { createTriageClient, triageItem } from './triage/llm.js';
import { matchTriage } from './triage/matcher.js';
import type { FeedItem } from './types.js';

/** Minimal .env loader (KEY=VALUE lines). Existing process env wins. */
function loadDotEnv(file: string): void {
  if (!existsSync(file)) return;
  for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (raw.trim().startsWith('#')) continue;
    const m = /^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/.exec(raw);
    if (!m) continue;
    if (process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

export const USAGE = `osmosecure <command> [options]

  init [--dir <path>] [--force]
      write a starter osmosecure.config.json and .env.example
  setup --code <code> --server <https url> [--dir <path>] [--force] [--allow-propose]
      exchange a one-time setup code for osmosecure.config.json (configuration only, no secrets).
      --server defaults to OSMOSECURE_SERVER. Refuses an existing config without --force.
      Access level 3 needs --allow-propose. Prints environment variable names to set, never values.
  scan [--llm] [--group a,b] [--json]
      read-only pass over every source group: public sources only, no state written, nothing sent.
      Triage is skipped unless --llm is given.
  watch [--once] [--tick-seconds <n>] [--no-llm] [--remediate-live]
      run source groups on their configured cadence. --once runs the groups that are due and exits
      (cron or CI); without it, loops every tick (default 60 seconds) until stopped.
  baseline [--no-llm]
      first-run mode: record every current finding and feed item as known, send nothing, print counts
  triage <file|-> [--source <name>]
      triage one disclosure text against your inventory and print the validated result and matches
  remediate <finding-key> [--live]
      build the remediation request for one finding; dry-run (print only) unless --live
  fix <finding-key> [--allow-major] [--base <local-branch>]
      isolated git worktree, bump ONE npm/pnpm dependency to the fixed version, run the tests, write a report,
      stop at awaiting-approval. Never pushes. Patch and minor bumps only unless --allow-major.
  fix --list | --approve <run> | --discard <run> | --publish <run>
      list runs; commit a reviewed run locally; remove a run; push the fix branch and open a draft PR
      (--publish needs fix.publish.enabled=true in the config and the gh CLI)
  fix-server
      receive signed osmosecure.remediation.v1 requests on loopback and start fixes (never approves or publishes)
  status
      last-run times and finding counts
global: --config <path>   (default ./osmosecure.config.json or OSMOSECURE_CONFIG)   --quiet
`;

const MAX_RUN_MS = 15 * 60_000;

function parseArgs(argv: string[]) {
  const [cmd, ...rest] = argv;
  const flag = (n: string) => rest.includes(`--${n}`);
  const val = (n: string) => {
    const i = rest.indexOf(`--${n}`);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const valueFlags = new Set(['config', 'group', 'dir', 'tick-seconds', 'source', 'approve', 'discard', 'publish', 'base', 'code', 'server']);
  const positional = rest.filter((a, i) => !a.startsWith('--') && !(i > 0 && valueFlags.has(rest[i - 1].replace(/^--/, '')) && rest[i - 1].startsWith('--')));
  return { cmd, flag, val, positional };
}

function load(val: (n: string) => string | undefined): Config {
  // The config directory is the only place a .env is read, so the config and its .env share one trust level. When no
  // --config or OSMOSECURE_CONFIG is given, the config is looked up in the current directory; that is convenient for
  // your own project folder, but a checkout you do not trust can ship its own config and .env. A config found that way
  // is therefore refused for module: backends (code execution); everything else in it is data. Name a config you trust
  // with --config in any directory you did not create.
  const config = loadConfig(val('config'));
  loadDotEnv(path.join(config.configDir, '.env'));
  return config;
}

function runOptions(over: Partial<RunOptions>): RunOptions {
  return { due: false, dryRun: false, remediateLive: false, noLlm: false, deadlineMs: MAX_RUN_MS - 60_000, ...over };
}

async function withDeadline<T>(fn: () => Promise<T>, log: ReturnType<typeof createLogger>): Promise<T> {
  const watchdog = setTimeout(() => {
    log.error('max run duration exceeded; aborting');
    process.exit(3);
  }, MAX_RUN_MS);
  watchdog.unref();
  try {
    return await fn();
  } finally {
    clearTimeout(watchdog);
  }
}

async function main(): Promise<number> {
  const { cmd, flag, val, positional } = parseArgs(process.argv.slice(2));
  const log = createLogger(flag('quiet'));

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    console.log(USAGE);
    return 0;
  }

  if (cmd === 'init') {
    const written = initProject(path.resolve(val('dir') ?? '.'), flag('force'));
    console.log(written.length ? `wrote:\n${written.map((w) => `  ${w}`).join('\n')}` : 'nothing written (files exist; use --force to overwrite)');
    return 0;
  }

  if (cmd === 'setup') {
    return runSetup(
      { code: val('code'), server: val('server'), dir: val('dir') ?? '.', force: flag('force'), allowPropose: flag('allow-propose') },
      { out: (l) => console.log(l), err: (l) => console.error(l) },
    );
  }

  const config = load(val);

  if (cmd === 'scan') {
    const groups = val('group')?.split(',').filter(Boolean);
    const summary = await withDeadline(
      () => runAudit(config, runOptions({ dryRun: true, noLlm: !flag('llm'), groups }), log),
      log,
    );
    if (flag('json') || !summary.message) console.log(JSON.stringify(summary, null, 2));
    else console.log(`${summary.message}\n\n${JSON.stringify({ ...summary, message: undefined }, null, 2)}`);
    return 0;
  }

  if (cmd === 'baseline') {
    const unlock = acquireLock(resolveDataDir(config));
    if (!unlock) throw new Error('another osmosecure run holds the lock');
    try {
      const summary = await withDeadline(() => runAudit(config, runOptions({ baseline: true, noLlm: flag('no-llm') }), log), log);
      console.log(JSON.stringify(summary, null, 2));
    } finally {
      unlock();
    }
    return 0;
  }

  if (cmd === 'watch') {
    const dataDir = resolveDataDir(config);
    const unlock = acquireLock(dataDir);
    if (!unlock) {
      log.warn('another osmosecure run holds the lock; exiting');
      return flag('once') ? 0 : 1;
    }
    let stop = false;
    for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => (stop = true));
    const tickMs = Math.max(10, Number(val('tick-seconds')) || 60) * 1000;
    const notifiers = createNotifiers(config);
    try {
      do {
        try {
          const summary = await runAudit(config, runOptions({ due: true, noLlm: flag('no-llm'), remediateLive: flag('remediate-live') }), log);
          if (summary.groupsRun.length) console.log(JSON.stringify({ ...summary, message: undefined }));
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          log.error('run failed', { error: msg });
          await sendAll(notifiers, `osmosecure run failed: ${msg.slice(0, 300)}`, log);
          if (flag('once')) return 1;
        }
        if (flag('once') || stop) break;
        for (let waited = 0; waited < tickMs && !stop; waited += 1000) await new Promise((r) => setTimeout(r, 1000));
      } while (!stop);
    } finally {
      unlock();
    }
    return 0;
  }

  if (cmd === 'triage') {
    const input = positional[0];
    if (!input) throw new Error('usage: osmosecure triage <file|->');
    const text = input === '-' ? readFileSync(0, 'utf8') : readFileSync(input, 'utf8');
    const client = await createTriageClient(config);
    if (!client) throw new Error('triage backend is not configured (see triage.backend and the .env template)');
    const inv = buildInventory(config, resolveDataDir(config), log);
    const item: FeedItem = {
      source: val('source') ?? 'manual',
      id: 'manual',
      title: text.split(/\r?\n/, 1)[0]?.slice(0, 200) ?? '',
      text,
      cves: [],
      productHints: [],
    };
    const result = await triageItem(client, item, config.triage.maxInputChars);
    const matches = result.relevant
      ? matchTriage(result.products, inv.components).map((m) => ({
          project: m.component.project,
          component: `${m.component.name}@${m.component.version}`,
          origin: m.component.origin,
          verdict: m.verdict,
          fixedVersion: m.fixedVersion,
          reason: m.reason,
        }))
      : [];
    console.log(JSON.stringify({ triage: result, matches }, null, 2));
    return 0;
  }

  if (cmd === 'remediate') {
    const key = positional[0];
    if (!key) throw new Error('finding key required');
    const store = new StateStore(resolveDataDir(config));
    const f = store.state.findings[key];
    if (!f) throw new Error('finding not found in state');
    const d = decide({ ...f, tier: 'page' }, config); // explicit approval overrides the tier gate only
    if (d.action === 'none') throw new Error(`not eligible: ${d.why}`);
    const request = buildRequest(f, d, config);
    const hook = hookReady(config);
    if (!flag('live') || !hook) {
      console.log(JSON.stringify({ dryRun: true, hookConfigured: Boolean(hook), request }, null, 2));
      return 0;
    }
    const ok = await postRequest(request, config, hook.secret, log);
    if (ok) {
      store.state.remediated[key] = { at: new Date().toISOString(), dryRun: false };
      store.save();
    }
    console.log(ok ? 'posted' : 'failed');
    return ok ? 0 : 1;
  }

  if (cmd === 'fix' || cmd === 'fix-server') {
    try {
      assertFixerAllowed(config);
    } catch (err) {
      console.error(`refused: ${err instanceof Error ? err.message : String(err)}`);
      return 1;
    }
  }

  if (cmd === 'fix') {
    const deps = { config, log };
    const show = (r: Parameters<typeof renderReport>[0]) => console.log(renderReport(r));
    try {
      if (flag('list')) {
        console.log(JSON.stringify(listRuns(config).map((r) => ({ id: r.id, status: r.status, package: r.package, from: r.from, to: r.to, advisory: r.advisoryId, reason: r.reason })), null, 2));
        return 0;
      }
      const approve = val('approve');
      const discard = val('discard');
      const publish = val('publish');
      if (approve) return show(await approveFix(deps, approve)), 0;
      if (discard) return show(await discardFix(deps, discard)), 0;
      if (publish) return show(await publishFix(deps, publish)), 0;
      const key = positional[0];
      if (!key) throw new FixRefusal('usage: osmosecure fix <finding-key> | --list | --approve <run> | --discard <run> | --publish <run>');
      const startOpts = { findingKey: key, allowMajor: flag('allow-major'), base: val('base') };
      const r = await startFix(deps, startOpts);
      show(r);
      return r.status === 'awaiting-approval' || r.status === 'published' ? 0 : 1;
    } catch (err) {
      if (err instanceof FixRefusal) {
        console.error(`refused: ${err.message}`);
        return 1;
      }
      throw err;
    }
  }

  if (cmd === 'fix-server') {
    const secret = process.env[config.remediation.hook.secretEnv];
    if (!secret) throw new Error(`${config.remediation.hook.secretEnv} is not set; the receiver will not start without a secret`);
    const { host, port } = config.fix.server;
    assertLoopbackHost(host);
    const server = startFixServer(config, secret, (key) => startFix({ config, log }, { findingKey: key }), log);
    server.listen(port, host, () => log.info('fix-server listening', { host, port }));
    for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => server.close(() => process.exit(0)));
    await new Promise(() => undefined);
  }

  if (cmd === 'status') {
    const store = new StateStore(resolveDataDir(config));
    const byTier: Record<string, number> = {};
    for (const f of Object.values(store.state.findings)) byTier[f.tier] = (byTier[f.tier] ?? 0) + 1;
    console.log(JSON.stringify({ lastRun: store.state.lastRun, findingsByTier: byTier, digestPending: store.state.digestPending.length }, null, 2));
    return 0;
  }

  console.error(USAGE);
  return 2;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  },
);
