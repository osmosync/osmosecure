import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { acquireLock } from './commands/lock.js';
import { expandPath, resolveDataDir, type Config } from './config.js';
import { describeSmoke, emptySmoke, isInstrumentationPackage, type SmokeReport } from './fix-smoke.js';
import { lockfileKind } from './inventory/lockfiles.js';
import { compareVersions, bumpClass } from './lib/version.js';
import { StateStore } from './state.js';
import { scrubSecrets } from './triage/scrub.js';
import type { Finding, Logger } from './types.js';

/**
 * Dependency-bump fixer. Deterministic: every command and argument is built from validated structured
 * fields of a finding already in local state. No model runs here and no advisory free text is read.
 * The pipeline stops at `awaiting-approval`; commit and publish are separate explicit steps.
 */

export type FixStatus = 'awaiting-approval' | 'approved' | 'published' | 'failed' | 'discarded';

export interface FixReport {
  schema: 'osmosecure.fix.v1';
  id: string;
  status: FixStatus;
  reason?: string;
  createdAt: string;
  updatedAt: string;
  findingKey: string;
  advisoryId: string;
  project: string;
  ecosystem: string;
  packageManager: string;
  package: string;
  from: string;
  to: string;
  bump: string;
  allowMajor: boolean;
  /** Directory of the manifest relative to the repository top level. */
  workdir: string;
  branch: string;
  baseCommit: string;
  repoRoot: string;
  worktree: string;
  changedFiles: string[];
  tests: { command: string[] | null; passed: boolean | null; exitCode: number | null; durationMs: number; outputTail: string };
  /** Runtime smoke check outcome (absent on reports written before the gate existed). */
  smoke?: SmokeReport;
  commit?: string;
  pr?: string;
  /** Why a run needs a person to take over. The local branch is kept. */
  needsHuman?: string;
}

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}
export interface ExecOptions {
  cwd: string;
  timeoutMs: number;
  env: NodeJS.ProcessEnv;
}
export type Exec = (cmd: string, args: string[], opts: ExecOptions) => Promise<ExecResult>;

/** Real process runner: no shell, stdin closed, bounded output, hard timeout. */
export const defaultExec: Exec = (cmd, args, opts) =>
  new Promise((resolve) => {
    const child = execFile(
      cmd,
      args,
      { cwd: opts.cwd, env: opts.env, timeout: opts.timeoutMs, maxBuffer: 8 * 1024 * 1024, killSignal: 'SIGKILL' },
      (err, stdout, stderr) => {
        const e = err as (NodeJS.ErrnoException & { killed?: boolean; code?: number | string }) | null;
        resolve({
          code: !e ? 0 : typeof e.code === 'number' ? e.code : null,
          stdout: String(stdout ?? ''),
          stderr: e && typeof e.code === 'string' ? `${e.code}: ${e.message}` : String(stderr ?? ''),
          timedOut: Boolean(e?.killed),
        });
      },
    );
    child.stdin?.end();
  });

/** Minimal environment for child processes: no ambient secrets unless named in fix.passEnv. */
export function childEnv(config: Config, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { CI: '1', GIT_TERMINAL_PROMPT: '0' };
  for (const k of ['PATH', 'HOME', 'LANG', 'TMPDIR', 'USER', 'SHELL', ...config.fix.passEnv]) {
    if (base[k] !== undefined) env[k] = base[k];
  }
  return env;
}

export class FixRefusal extends Error {}

export const PKG_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
export const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$/;
export const SAFE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/;

export function slug(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').replace(/\.{2,}/g, '.').slice(0, 80);
}

/** `where` (the manifest directory) keeps the same advisory and package in different lockfiles from colliding. */
export function branchFor(advisoryId: string, pkg: string, where = ''): string {
  const w = slug(where.split(/[\\/]/).join('-'));
  return `osmosecure/fix-${slug(advisoryId)}-${slug(pkg)}${w ? `-${w}` : ''}`;
}

export function runIdFor(branch: string): string {
  return branch.replace(/^osmosecure\//, '').replace(/\//g, '-');
}

export interface FixDirs {
  base: string;
  runs: string;
  worktrees: string;
}
export function fixDirs(config: Config): FixDirs {
  const base = path.join(resolveDataDir(config), 'fix');
  return {
    base,
    runs: path.join(base, 'runs'),
    worktrees: config.fix.worktreeRoot ? expandPath(config.fix.worktreeRoot, config.configDir) : path.join(base, 'worktrees'),
  };
}

export type PackageManager = 'npm' | 'pnpm';

export function packageManagerFor(lockBasename: string): PackageManager {
  if (lockBasename === 'package-lock.json' || lockBasename === 'npm-shrinkwrap.json') return 'npm';
  if (lockBasename === 'pnpm-lock.yaml') return 'pnpm';
  if (lockBasename === 'yarn.lock') throw new FixRefusal('yarn lockfiles are not supported by the fixer yet (npm and pnpm only)');
  throw new FixRefusal(`unsupported lockfile ${lockBasename}: the fixer handles npm and pnpm only in this version`);
}

/** Install command argv. Scripts are disabled so a bump never executes dependency lifecycle code. */
export function bumpCommand(pm: PackageManager, pkg: string, version: string, section: 'dependencies' | 'devDependencies' | 'optionalDependencies'): string[] {
  if (!PKG_RE.test(pkg) || !VERSION_RE.test(version)) throw new FixRefusal('package name or version failed validation'); // a leading "-" can never become a flag
  const spec = `${pkg}@${version}`;
  if (pm === 'npm') return ['npm', 'install', spec, '--ignore-scripts', '--no-audit', '--no-fund'];
  const flag = section === 'devDependencies' ? ['-D'] : section === 'optionalDependencies' ? ['-O'] : [];
  return ['pnpm', 'add', spec, '--ignore-scripts', ...flag];
}

/** Transitive update argv: lets the package manager move the package inside its parents' ranges; only the lockfile changes. */
export function updateCommand(pm: PackageManager, pkg: string): string[] {
  if (!PKG_RE.test(pkg)) throw new FixRefusal('package name failed validation');
  if (pm === 'npm') return ['npm', 'update', pkg, '--ignore-scripts', '--no-audit', '--no-fund'];
  return ['pnpm', 'update', pkg, '--depth', 'Infinity', '--ignore-scripts'];
}

/** Reinstall argv used after an overrides entry was written. */
export function reinstallCommand(): string[] {
  return ['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund'];
}

export const majorOf = (v: string): string => v.split('.')[0];
/** Versions in the same major line as the fixed version: other major lines have their own fixes and are not judged here. */
export function sameLine(versions: string[], to: string): string[] {
  return versions.filter((v) => majorOf(v) === majorOf(to));
}

export function tail(s: string, n = 4000): string {
  return s.length > n ? s.slice(s.length - n) : s;
}

export function now(deps: FixDeps): Date {
  return deps.now ? deps.now() : new Date();
}

export interface FixDeps {
  config: Config;
  log: Logger;
  exec?: Exec;
  now?: () => Date;
  env?: NodeJS.ProcessEnv;
}

export function sh(deps: FixDeps) {
  const exec = deps.exec ?? defaultExec;
  const env = childEnv(deps.config, deps.env);
  return (cwd: string, cmd: string, args: string[], timeoutMs = 60_000) => exec(cmd, args, { cwd, timeoutMs, env });
}

export async function git(deps: FixDeps, cwd: string, args: string[], timeoutMs = 60_000): Promise<string> {
  const r = await sh(deps)(cwd, 'git', args, timeoutMs);
  if (r.code !== 0) throw new Error(`git ${args[0]} failed: ${scrubSecrets(tail(r.stderr || r.stdout, 400), deps.env ?? process.env)}`);
  return r.stdout.trim();
}

function runFile(dirs: FixDirs, id: string): string {
  return path.join(dirs.runs, `${id}.json`);
}

function sanitizeRun(r: FixReport): FixReport {
  return r;
}

export function loadRun(config: Config, id: string): FixReport {
  if (!SAFE_ID_RE.test(id)) throw new FixRefusal('invalid run id');
  const file = runFile(fixDirs(config), id);
  if (!existsSync(file)) throw new FixRefusal(`no such run: ${id}`);
  return sanitizeRun(JSON.parse(readFileSync(file, 'utf8')) as FixReport);
}

export function listRuns(config: Config): FixReport[] {
  const dir = fixDirs(config).runs;
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => sanitizeRun(JSON.parse(readFileSync(path.join(dir, f), 'utf8')) as FixReport))
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export function renderReport(r: FixReport): string {
  return [
    `# osmosecure fix ${r.id}`,
    '',
    `- Status: ${r.status}${r.reason ? ` (${r.reason})` : ''}`,
    `- Advisory: ${r.advisoryId}`,
    `- Package: ${r.package} (${r.ecosystem}, ${r.packageManager}) ${r.from} -> ${r.to} (${r.bump} bump)`,
    `- Project: ${r.project}, manifest directory: ${r.workdir || '.'}`,
    `- Branch: ${r.branch} (base ${r.baseCommit.slice(0, 12)})`,
    `- Changed files: ${r.changedFiles.join(', ') || 'none'}`,
    `- Tests: ${r.tests.passed === null ? 'not run' : r.tests.passed ? 'passed' : 'FAILED'}${r.tests.command ? ` (${r.tests.command.join(' ')}, exit ${r.tests.exitCode}, ${r.tests.durationMs} ms)` : ''}`,
    `- Smoke check: ${describeSmoke(r.smoke)}`,
    r.commit ? `- Commit: ${r.commit}` : '',
    r.pr ? `- Pull request: ${r.pr}` : '',
    r.needsHuman ? `- Needs a human: ${r.needsHuman}` : '',
    '',
    r.status === 'awaiting-approval'
      ? `Review the worktree at ${r.worktree}, then run: osmosecure fix --approve ${r.id}`
      : '',
    '',
  ]
    .filter((l, i, a) => l !== '' || a[i - 1] !== '')
    .join('\n');
}

export function saveRun(config: Config, r: FixReport, at: Date): void {
  const dirs = fixDirs(config);
  mkdirSync(dirs.runs, { recursive: true, mode: 0o700 });
  r.updatedAt = at.toISOString();
  writeFileSync(runFile(dirs, r.id), JSON.stringify(r, null, 2), { mode: 0o600 });
  writeFileSync(path.join(dirs.runs, `${r.id}.md`), renderReport(r), { mode: 0o600 });
}

export function manifestSection(pkgJson: Record<string, unknown>, pkg: string): 'dependencies' | 'devDependencies' | 'optionalDependencies' | null {
  for (const s of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
    const sec = pkgJson[s];
    if (sec && typeof sec === 'object' && Object.prototype.hasOwnProperty.call(sec, pkg)) return s;
  }
  return null;
}

export function lockVersions(lockText: string, lockBasename: string, pkg: string): string[] {
  const kind = lockfileKind(lockBasename);
  if (!kind) return [];
  return kind.parse(lockText, true).filter((c) => c.name === pkg).map((c) => c.version);
}

export interface StartOptions {
  findingKey: string;
  allowMajor?: boolean;
  /** Stack on an existing local branch or commit (for example a previous fix branch) instead of HEAD. */
  base?: string;
}

/** Validates a finding and runs bump + tests in an isolated worktree. Returns the stored report. */
export async function startFix(deps: FixDeps, opts: StartOptions): Promise<FixReport> {
  const { config, log } = deps;
  const run = sh(deps);
  const dirs = fixDirs(config);
  const store = new StateStore(resolveDataDir(config));
  const f: Finding | undefined = Object.hasOwn(store.state.findings, opts.findingKey) ? store.state.findings[opts.findingKey] : undefined;
  if (!f) throw new FixRefusal('finding not found in state');
  if (f.basis !== 'deterministic' || f.component.kind !== 'package') throw new FixRefusal('only deterministic application-dependency findings can be fixed');
  if (f.component.ecosystem !== 'npm') throw new FixRefusal(`ecosystem ${f.component.ecosystem} is not supported by the fixer yet (npm and pnpm only)`);
  if (!f.fixedVersion) throw new FixRefusal('no fixed version known for this finding');
  const pkg = f.component.name;
  const from = f.component.version;
  const to = f.fixedVersion;
  if (!PKG_RE.test(pkg)) throw new FixRefusal('package name failed validation');
  if (!VERSION_RE.test(to) || !VERSION_RE.test(from)) throw new FixRefusal('version is not a plain semver release (pre-release ranges and tags are refused)');
  if (!SAFE_ID_RE.test(f.advisoryId)) throw new FixRefusal('advisory id failed validation');
  const bump = bumpClass(from, to);
  if (bump === 'unknown') throw new FixRefusal('fixed version is not newer than the current version');
  if (bump === 'major' && !opts.allowMajor) throw new FixRefusal('major bump refused; pass --allow-major to proceed');

  const proj = config.projects.find((p) => p.id === f.component.project);
  if (!proj) throw new FixRefusal(`project ${f.component.project} is not in the config`);
  const lockRel = f.component.origin;
  if (path.isAbsolute(lockRel) || lockRel.split(/[\\/]/).includes('..')) throw new FixRefusal('lockfile origin path is not project-relative');
  const lockBase = path.basename(lockRel);
  const pm = packageManagerFor(lockBase);
  const projRoot = realpathSync(expandPath(proj.root, config.configDir));
  const repoRoot = realpathSync(await git(deps, projRoot, ['rev-parse', '--show-toplevel']));
  const workdir = path.relative(repoRoot, path.join(projRoot, path.dirname(lockRel)));
  if (workdir.startsWith('..') || path.isAbsolute(workdir)) throw new FixRefusal('manifest directory escapes the repository');

  const dirty = await git(deps, repoRoot, ['status', '--porcelain', '--untracked-files=no']);
  if (dirty) throw new FixRefusal('the project checkout has uncommitted changes to tracked files; commit or stash them first (the fixer never touches a dirty checkout)');

  const branch = branchFor(f.advisoryId, pkg, workdir === '.' ? '' : workdir);
  await git(deps, repoRoot, ['check-ref-format', '--branch', branch]);
  const id = runIdFor(branch);
  const existing = existsSync(runFile(dirs, id)) ? loadRun(config, id) : null;
  if (existing && existing.status !== 'failed' && existing.status !== 'discarded') throw new FixRefusal(`run ${id} already exists (${existing.status})`);
  if ((await sh(deps)(repoRoot, 'git', ['rev-parse', '--verify', '--quiet', `refs/heads/${branch}`])).code === 0) {
    throw new FixRefusal(`branch ${branch} already exists in the repository`);
  }

  const runs = listRuns(config);
  const cutoff = now(deps).getTime() - 86_400_000;
  if (runs.filter((r) => Date.parse(r.createdAt) >= cutoff).length >= config.fix.maxRunsPerDay) throw new FixRefusal(`run cap reached (${config.fix.maxRunsPerDay} per 24 hours)`);
  if (runs.filter((r) => r.status === 'awaiting-approval').length >= config.fix.maxOpenRuns) throw new FixRefusal(`${config.fix.maxOpenRuns} runs already await approval; approve or discard one first`);

  const unlock = acquireLock(dirs.base);
  if (!unlock) throw new FixRefusal('another fix run holds the lock');
  const worktree = path.join(dirs.worktrees, id);
  if (opts.base !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._\/-]{0,200}$/.test(opts.base)) throw new FixRefusal('invalid --base ref');
  const baseCommit = await git(deps, repoRoot, ['rev-parse', '--verify', `${opts.base ?? 'HEAD'}^{commit}`]);
  const report: FixReport = {
    schema: 'osmosecure.fix.v1',
    id,
    status: 'failed',
    createdAt: now(deps).toISOString(),
    updatedAt: '',
    findingKey: f.key,
    advisoryId: f.advisoryId,
    project: proj.id,
    ecosystem: f.component.ecosystem,
    packageManager: pm,
    package: pkg,
    from,
    to,
    bump,
    allowMajor: Boolean(opts.allowMajor),
    workdir,
    branch,
    baseCommit,
    repoRoot,
    worktree,
    changedFiles: [],
    tests: { command: null, passed: null, exitCode: null, durationMs: 0, outputTail: '' },
    smoke: emptySmoke(),
  };

  const fail = async (reason: string): Promise<FixReport> => {
    report.status = 'failed';
    report.reason = reason;
    await removeWorktree(deps, report).catch(() => undefined);
    saveRun(config, report, now(deps));
    log.warn('fix failed', { run: id, reason });
    return report;
  };

  try {
    mkdirSync(dirs.worktrees, { recursive: true, mode: 0o700 });
    await git(deps, repoRoot, ['worktree', 'add', '-b', branch, worktree, baseCommit], 120_000);
    const wd = path.join(worktree, workdir);
    if (existsSync(wd) && !(realpathSync(wd) + path.sep).startsWith(realpathSync(worktree) + path.sep)) return await fail('manifest directory resolves outside the worktree (symlink)');
    const manifest = path.join(wd, 'package.json');
    const lockFile = path.join(wd, lockBase);
    if (!existsSync(manifest) || !existsSync(lockFile)) return await fail('package.json or lockfile missing at the recorded path in the base commit');

    const pkgJson = JSON.parse(readFileSync(manifest, 'utf8')) as Record<string, unknown>;
    const section = manifestSection(pkgJson, pkg);
    const lineOf = (vs: string[]): string[] => (bump === 'major' ? vs : sameLine(vs, to));
    const present = lineOf(lockVersions(readFileSync(lockFile, 'utf8'), lockBase, pkg));
    if (present.length === 0) return await fail('package not found in the lockfile at the base commit (finding is stale)');
    if (present.every((v) => (compareVersions(v, to) ?? -1) >= 0)) return await fail('already at or above the fixed version in the lockfile');

    const failBump = async (r: ExecResult): Promise<FixReport> => {
      report.tests.outputTail = scrubSecrets(tail(`${r.stdout}\n${r.stderr}`), deps.env ?? process.env);
      return fail(r.timedOut ? 'package manager timed out' : 'package manager command failed');
    };
    /** null = fixed; otherwise the versions of the fixed major line that remain (empty = package vanished). */
    const stillBelow = (): string[] | null => {
      const after = lineOf(lockVersions(readFileSync(lockFile, 'utf8'), lockBase, pkg));
      return after.length === 0 || after.some((v) => (compareVersions(v, to) ?? -1) < 0) ? [...new Set(after)] : null;
    };
    const belowMsg = (b: string[]): string => `lockfile still resolves ${pkg} below ${to}: ${b.join(', ') || 'none'}`;

    if (section) {
      const [cmd, ...args] = bumpCommand(pm, pkg, to, section);
      const bumped = await run(wd, cmd, args, config.fix.installTimeoutMs);
      if (bumped.code !== 0) return await failBump(bumped);
      const below = stillBelow();
      if (below) return await fail(belowMsg(below));
    } else {
      // Transitive: let the package manager move it inside its parents' ranges (lockfile only).
      const [ucmd, ...uargs] = updateCommand(pm, pkg);
      const upd = await run(wd, ucmd, uargs, config.fix.installTimeoutMs);
      if (upd.code !== 0) return await failBump(upd);
      let below = stillBelow();
      if (below) {
        // A parent range blocks the fix. npm only: pin the package with an overrides entry, but only when
        // the tree holds a single major line of it so no dependent is forced across a major.
        const all = lockVersions(readFileSync(lockFile, 'utf8'), lockBase, pkg);
        const existing = (pkgJson.overrides as Record<string, unknown> | undefined) ?? {};
        if (pm !== 'npm') return await fail(`${belowMsg(below)}; a parent range blocks the fix and overrides are only automated for npm`);
        if (all.some((v) => majorOf(v) !== majorOf(to) && bump !== 'major')) return await fail(`${belowMsg(below)}; the tree has several major lines of ${pkg}, so an override is not applied automatically`);
        if (Object.prototype.hasOwnProperty.call(existing, pkg)) return await fail(`${belowMsg(below)}; package.json already has an overrides entry for ${pkg}`);
        if (isInstrumentationPackage(pkg) && !config.fix.smokeCommand) return await fail(`skipped: needs parent upgrade or human review (override for instrumentation package ${pkg} requires fix.smokeCommand)`);
        pkgJson.overrides = { ...existing, [pkg]: `^${to}` };
        writeFileSync(manifest, JSON.stringify(pkgJson, null, detectIndent(readFileSync(manifest, 'utf8'))) + '\n');
        const [rcmd, ...rargs] = reinstallCommand();
        const re = await run(wd, rcmd, rargs, config.fix.installTimeoutMs);
        if (re.code !== 0) return await failBump(re);
        below = stillBelow();
        if (below) return await fail(belowMsg(below));
      }
    }

    const fin = await verifyChanges(deps, report, { wd, worktree, workdir, lockBase, manifest, pm, fail });
    if (fin) return fin;

    // node_modules is untracked and regenerable; keeping one per open run fills the disk.
    rmSync(path.join(wd, 'node_modules'), { recursive: true, force: true });
    report.status = 'awaiting-approval';
    saveRun(config, report, now(deps));
    log.info('fix ready for approval', { run: id });
    return report;
  } catch (err) {
    return await fail(`error: ${scrubSecrets(err instanceof Error ? err.message : String(err), deps.env ?? process.env).slice(0, 300)}`);
  } finally {
    unlock();
  }
}

/** Marks a run failed, removes its worktree and branch, and stores the report. */
export async function failRun(deps: FixDeps, report: FixReport, reason: string): Promise<FixReport> {
  report.status = 'failed';
  report.reason = reason;
  await removeWorktree(deps, report).catch(() => undefined);
  saveRun(deps.config, report, now(deps));
  deps.log.warn('fix failed', { run: report.id, reason });
  return report;
}

export interface VerifyCtx {
  wd: string;
  worktree: string;
  workdir: string;
  lockBase: string;
  manifest: string;
  pm: PackageManager;
  fail: (reason: string) => Promise<FixReport>;
  /** Extra repository-relative paths (posix) a run may legitimately change, for example a patches/ file. */
  extraAllowed?: string[];
}

/**
 * Shared gate after the package manager ran: only the manifest, the lockfile and explicitly allowed files changed,
 * then tests and the smoke check. Returns a failed report, or null when everything passed.
 */
export async function verifyChanges(deps: FixDeps, report: FixReport, c: VerifyCtx): Promise<FixReport | null> {
  const { config } = deps;
  const run = sh(deps);
  const { wd, worktree, workdir, lockBase, manifest, pm, fail } = c;
    const allowed = new Set([path.posix.join(workdir.split(path.sep).join('/'), 'package.json'), path.posix.join(workdir.split(path.sep).join('/'), lockBase), ...(c.extraAllowed ?? [])].map((p) => p.replace(/^\.\//, '')));
    const changed = (await git(deps, worktree, ['diff', '--name-only', 'HEAD'])).split('\n').filter(Boolean);
    report.changedFiles = changed;
    const stray = changed.filter((c) => !allowed.has(c));
    if (stray.length) return fail(`unexpected files changed: ${stray.slice(0, 5).join(', ')}`);
    if (!changed.length) return fail('package manager made no change');

    const testCmd = await resolveTestCommand(config, pm, manifest);
    if (testCmd) {
      report.tests.command = testCmd;
      const t0 = Date.now();
      const r = await run(wd, testCmd[0], testCmd.slice(1), config.fix.testTimeoutMs);
      report.tests.durationMs = Date.now() - t0;
      report.tests.exitCode = r.code;
      report.tests.passed = r.code === 0;
      report.tests.outputTail = scrubSecrets(tail(`${r.stdout}\n${r.stderr}`), deps.env ?? process.env);
      if (!report.tests.passed) return fail(r.timedOut ? 'tests timed out' : 'tests failed');
    } else if (config.autoFix.requireTestsPass) {
      return fail('no test command (set fix.testCommand or add scripts.test); autoFix.requireTestsPass is true');
    }

    if (config.fix.smokeCommand) {
      const sc = config.fix.smokeCommand;
      const sm: SmokeReport = { ...emptySmoke(), result: 'fail', command: sc };
      report.smoke = sm;
      const t1 = Date.now();
      const sr = await run(wd, sc[0], sc.slice(1), config.fix.smokeTimeoutMs);
      sm.durationMs = Date.now() - t1;
      sm.exitCode = sr.code;
      sm.timedOut = sr.timedOut;
      sm.result = sr.code === 0 && !sr.timedOut ? 'pass' : 'fail';
      if (sm.result === 'fail') return fail(sr.timedOut ? 'smoke check timed out' : 'smoke check failed');
    }

  return null;
}

export function detectIndent(text: string): number | string {
  const m = /^([ \t]+)"/m.exec(text);
  return m ? m[1] : 2;
}

export async function resolveTestCommand(config: Config, pm: PackageManager, manifest: string): Promise<string[] | null> {
  if (config.fix.testCommand) return config.fix.testCommand;
  const scripts = (JSON.parse(readFileSync(manifest, 'utf8')) as { scripts?: Record<string, string> }).scripts;
  if (scripts?.test) return [pm, 'test'];
  // No test script: fall back to the strongest static check the project defines (type check, then build).
  for (const name of ['typecheck', 'check', 'build']) if (scripts?.[name]) return [pm, 'run', name];
  return null;
}

export async function removeWorktree(deps: FixDeps, r: FixReport): Promise<void> {
  if (existsSync(r.worktree)) await git(deps, r.repoRoot, ['worktree', 'remove', '--force', r.worktree], 120_000);
  await git(deps, r.repoRoot, ['worktree', 'prune']).catch(() => undefined);
  if ((await sh(deps)(r.repoRoot, 'git', ['rev-parse', '--verify', '--quiet', `refs/heads/${r.branch}`])).code === 0) {
    await git(deps, r.repoRoot, ['branch', '-D', r.branch]);
  }
}

/** Commits the reviewed change locally on the fix branch. Stages only the manifest and lockfile. */
export async function approveFix(deps: FixDeps, id: string): Promise<FixReport> {
  const { config } = deps;
  const r = loadRun(config, id);
  if (r.status !== 'awaiting-approval') throw new FixRefusal(`run is ${r.status}, not awaiting-approval`);
  if (r.tests.passed !== true && config.autoFix.requireTestsPass) throw new FixRefusal('tests did not pass for this run');
  if (!existsSync(r.worktree)) throw new FixRefusal('worktree is gone; discard and rerun');
  const head = await git(deps, r.worktree, ['rev-parse', 'HEAD']);
  if (head !== r.baseCommit) throw new FixRefusal('worktree HEAD moved since the run; discard and rerun');
  const branchNow = await git(deps, r.worktree, ['rev-parse', '--abbrev-ref', 'HEAD']);
  if (branchNow !== r.branch) throw new FixRefusal('worktree is not on the fix branch');
  const changed = (await git(deps, r.worktree, ['diff', '--name-only', 'HEAD'])).split('\n').filter(Boolean);
  if (changed.length !== r.changedFiles.length || changed.some((c) => !r.changedFiles.includes(c))) throw new FixRefusal('worktree changes differ from the reported change; discard and rerun');
  const staged = await git(deps, r.worktree, ['diff', '--cached', '--name-only']);
  if (staged) throw new FixRefusal('unexpected staged changes in the worktree');
  await git(deps, r.worktree, ['add', '--', ...r.changedFiles]);
  const message = `security: bump ${r.package} ${r.from} -> ${r.to} (${r.advisoryId})\n\nGenerated by osmosecure fix ${r.id}. Tests: ${r.tests.passed ? 'passed' : 'not run'}.`;
  await git(deps, r.worktree, ['-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', message]);
  r.commit = await git(deps, r.worktree, ['rev-parse', 'HEAD']);
  r.status = 'approved';
  saveRun(config, r, now(deps));
  return r;
}

/** Explicit publish: pushes only the fix branch (never forced) and opens a draft PR with gh. Off unless fix.publish.enabled. */
export async function publishFix(deps: FixDeps, id: string): Promise<FixReport> {
  const { config } = deps;
  if (!config.fix.publish.enabled) throw new FixRefusal('publishing is disabled; set fix.publish.enabled to true to allow it');
  const r = loadRun(config, id);
  if (r.status !== 'approved' || !r.commit) throw new FixRefusal(`run is ${r.status}; approve it first`);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(config.fix.publish.remote)) throw new FixRefusal('invalid remote name');
  if (!r.branch.startsWith('osmosecure/fix-')) throw new FixRefusal('refusing to push a non-fix branch');
  const run = sh(deps);
  if ((await run(r.worktree, 'gh', ['--version'], 15_000)).code !== 0) throw new FixRefusal('gh CLI not found on PATH; install and authenticate it, or push the branch yourself');
  const head = await git(deps, r.worktree, ['rev-parse', 'HEAD']);
  if (head !== r.commit) throw new FixRefusal('branch HEAD differs from the approved commit');
  await git(deps, r.worktree, ['push', '--no-verify', '--', config.fix.publish.remote, `refs/heads/${r.branch}:refs/heads/${r.branch}`], 120_000);
  const body = [
    `Automated dependency bump from osmosecure (${r.id}).`,
    '',
    `- Advisory: ${r.advisoryId}`,
    `- ${r.package}: ${r.from} -> ${r.to} (${r.bump})`,
    `- Tests: ${r.tests.passed ? 'passed' : 'not run'}`,
    '',
    'Review before merging. osmosecure does not merge or deploy.',
  ].join('\n');
  const pr = await run(r.worktree, 'gh', ['pr', 'create', '--draft', '--head', r.branch, '--title', `security: bump ${r.package} to ${r.to} (${r.advisoryId})`, '--body', body], 60_000);
  if (pr.code !== 0) throw new FixRefusal(`branch pushed but gh pr create failed: ${scrubSecrets(tail(pr.stderr, 300), deps.env ?? process.env)}`);
  r.pr = pr.stdout.trim().split('\n').pop();
  r.status = 'published';
  saveRun(config, r, now(deps));
  return r;
}

/** Removes the worktree and local branch of a run that is not published. */
export async function discardFix(deps: FixDeps, id: string): Promise<FixReport> {
  const r = loadRun(deps.config, id);
  if (r.status === 'published') throw new FixRefusal('run is published; close the PR instead');
  await removeWorktree(deps, r);
  r.status = 'discarded';
  saveRun(deps.config, r, now(deps));
  return r;
}
