import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { DEFAULTS, deepMerge } from './defaults.js';

export const CONFIG_FILENAME = 'osmosecure.config.json';

const tierEnum = z.enum(['page', 'alert', 'digest', 'log']);

const notifierSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('stdout') }),
  /** Generic JSON webhook: POST {"text": "..."}; the URL comes from an environment variable. */
  z.object({ type: z.literal('webhook'), urlEnv: z.string().default('OSMOSECURE_WEBHOOK_URL') }),
  /** Slack incoming webhook: POST {"text": "..."}; the URL comes from an environment variable. */
  z.object({ type: z.literal('slack'), urlEnv: z.string().default('SLACK_WEBHOOK_URL') }),
  /** Telegram Bot API; the token and chat id come from the environment variables named by tokenEnv and chatIdEnv. */
  z.object({
    type: z.literal('telegram'),
    tokenEnv: z.string().min(1).default('TELEGRAM_BOT_TOKEN'),
    chatIdEnv: z.string().min(1).default('TELEGRAM_CHAT_ID'),
  }),
]);

export const configSchema = z.object({
  schemaVersion: z.literal(1),
  /** Resolved by loadConfig to the directory holding the config file; relative paths are relative to it. */
  configDir: z.string().default('.'),
  /** Set by loadConfig only (never read from the file): the config was found by default in the current directory, not named by --config or OSMOSECURE_CONFIG. */
  implicitCwd: z.boolean().default(false),
  dataDir: z.string().default('.osmosecure'),
  /**
   * 1 = read-only, no alerts sent; 2 = alerts; 3 = alerts plus the fixer, only with allowPropose=true.
   * Level 4 and above is refused. Absent keeps the pre-setup behaviour (alerts on, fixer available).
   */
  accessLevel: z.number().int().min(1).max(3).optional(),
  /** Must be true, together with accessLevel 3, before the fix and fix-server commands run. */
  allowPropose: z.boolean().default(false),
  sourceGroups: z.record(z.string(),
    z.object({ everyMinutes: z.number().int().positive(), sources: z.array(z.string()).min(1) }),
  ),
  projects: z.array(
    z.object({
      id: z.string().min(1),
      root: z.string().min(1),
      /** Default remediation target name sent to the remediation hook for this project; null disables hand-off. */
      target: z.string().nullable().default(null),
      /** Path prefix relative to the project root -> target name (longest prefix wins). */
      pathTargets: z.record(z.string(), z.string()).prefault({}),
      maxDepth: z.number().int().min(1).max(10).default(4),
      skipDirs: z.array(z.string()).default(['node_modules', '.git', 'dist', 'build', '.next', 'tmp']),
      optional: z.boolean().default(false),
    }),
  ).default([]),
  /** JSON inventory files in the skill inventory format (see skill/inventory-schema.json). */
  inventoryFiles: z.array(z.string()).default([]),
  hosts: z.array(z.object({ id: z.string(), role: z.string().optional() })).default([]),
  localRuntimes: z.object({ includeNode: z.boolean().default(true) }).prefault({}),
  thresholds: z.object({ page: z.number(), alert: z.number(), digest: z.number() }),
  scoring: z.object({
    severity: z.object({
      critical: z.number(),
      high: z.number(),
      medium: z.number(),
      low: z.number(),
      unknown: z.number(),
    }),
    kevBoost: z.number(),
    epss: z.array(z.object({ min: z.number(), boost: z.number() })),
    runtimeBoost: z.number().default(0),
    unverifiedPenalty: z.number().default(0),
  }),
  autoFix: z.object({
    patchBumpsQueued: z.boolean(),
    requireTestsPass: z.boolean(),
    nonPatchRequiresApproval: z.boolean(),
    neverPushOrDeploy: z.literal(true),
  }),
  remediation: z.object({
    dryRun: z.boolean().default(true),
    minTier: tierEnum.default('alert'),
    maxPerRun: z.number().int().nonnegative().default(3),
    /** Signed webhook that receives remediation requests. Leave url empty to disable hand-off. */
    hook: z
      .object({
        url: z.string().default(''),
        /** Environment variable holding the HMAC secret. The secret itself never lives in the config. */
        secretEnv: z.string().default('OSMOSECURE_HOOK_SECRET'),
      })
      .prefault({}),
  }),
  /** Local dependency-bump fixer (`osmosecure fix`). Nothing here enables pushing unless publish.enabled is set. */
  fix: z
    .object({
      /** argv for the project test command (no shell). null = `<pm> test` when package.json defines scripts.test. */
      testCommand: z.array(z.string().min(1)).nullable().default(null),
      testTimeoutMs: z.number().int().positive().default(600_000),
      installTimeoutMs: z.number().int().positive().default(300_000),
      /** Optional runtime smoke check (argv, never a shell string), run in the worktree after install and tests. */
      smokeCommand: z.array(z.string().min(1)).min(1).nullable().default(null),
      smokeTimeoutMs: z.number().int().positive().default(120_000),
      /** Cap on fix runs created per rolling 24 hours, and on runs waiting for a human. */
      maxRunsPerDay: z.number().int().nonnegative().default(3),
      maxOpenRuns: z.number().int().nonnegative().default(3),
      /** Where isolated worktrees live. null = <dataDir>/fix/worktrees. */
      worktreeRoot: z.string().nullable().default(null),
      /** Extra environment variable names handed to package manager and test processes (for example a registry token name). */
      passEnv: z.array(z.string()).default([]),
      publish: z.object({ enabled: z.boolean().default(false), remote: z.string().default('origin') }).prefault({}),
      server: z
        .object({
          host: z.string().default('127.0.0.1'),
          port: z.number().int().min(1).max(65535).default(8787),
          timestampWindowSeconds: z.number().int().positive().default(300),
        })
        .prefault({}),
    })
    .prefault({}),
  notify: z.object({
    notifiers: z.array(notifierSchema).default([{ type: 'stdout' }]),
    maxFindingsPerMessage: z.number().int().positive().default(10),
  }),
  scan: z.object({
    prefer: z.enum(['auto', 'api', 'osv-scanner']).default('auto'),
    maxDetailFetchPerRun: z.number().int().positive().default(400),
    includeDevDependencies: z.boolean().default(false),
  }),
  feeds: z.object({
    lookbackDays: z.number().positive(),
    userAgent: z.string(),
    /** Allow feed hosts (and redirects) that resolve to loopback or private addresses. Off unless you mirror feeds internally. */
    allowPrivateNetwork: z.boolean().default(false),
    minIntervalMs: z.record(z.string(), z.number()),
    kev: z.object({ url: z.string().url() }),
    osv: z.object({
      baseUrl: z.string().url(),
      apiUrl: z.string().url(),
      ecosystems: z.array(z.string()),
      maxIdsPerRun: z.number().int().positive(),
    }),
    ghsa: z.object({ url: z.string().url(), perPage: z.number().int().positive() }),
    nvd: z.object({ url: z.string().url(), maxResults: z.number().int().positive().max(2000), maxPages: z.number().int().positive().default(3) }),
    epss: z.object({ url: z.string().url(), batchSize: z.number().int().positive() }),
    rss: z.array(
      z.object({
        id: z.string(),
        name: z.string(),
        url: z.string(),
        enabled: z.boolean(),
        todo: z.string().optional(),
      }),
    ),
  }),
  triage: z.object({
    /** claude-cli, anthropic-api, or module:<path> exporting a backend factory. TRIAGE_BACKEND env overrides built-in names only; module: must be set here. */
    backend: z.string().default('claude-cli'),
    maxItemsPerRun: z.number().int().positive(),
    maxInputChars: z.number().int().positive(),
    maxOutputTokens: z.number().int().positive(),
  }),
});

export type Config = z.infer<typeof configSchema>;

/** Throws when the access level does not permit the fixer commands (fix, fix-server). */
export function assertFixerAllowed(config: Pick<Config, 'accessLevel' | 'allowPropose'>): void {
  const level = config.accessLevel;
  if (level === undefined) return;
  if (level < 3) throw new Error(`access level ${level} does not allow the fixer commands; level 3 is required`);
  if (!config.allowPropose) throw new Error('access level 3 needs "allowPropose": true in the config before the fixer commands run');
}

export function expandPath(p: string, base: string): string {
  if (p === '~' || p.startsWith('~/')) return path.join(homedir(), p.slice(1));
  return path.isAbsolute(p) ? p : path.resolve(base, p);
}

/** Config lookup order: explicit path, OSMOSECURE_CONFIG, ./osmosecure.config.json. */
export function findConfigPath(explicit?: string, cwd = process.cwd()): string {
  const file = explicit ?? process.env.OSMOSECURE_CONFIG ?? path.join(cwd, CONFIG_FILENAME);
  const abs = path.resolve(cwd, file);
  if (!existsSync(abs)) throw new Error(`config not found: ${abs} (run "osmosecure init" to create one)`);
  return abs;
}

/** Validates a raw config object on top of the built-in defaults. */
export function parseConfig(raw: Record<string, unknown>, configDir: string, implicitCwd = false): Config {
  const lvl = raw.accessLevel;
  if (typeof lvl === 'number' && lvl > 3) throw new Error(`access level ${lvl} is not supported; refusing (levels 1 to 3 only)`);
  return configSchema.parse(deepMerge(DEFAULTS, { schemaVersion: 1, ...raw, configDir, implicitCwd }));
}

export function loadConfig(file?: string): Config {
  const abs = findConfigPath(file);
  const implicit = file === undefined && !process.env.OSMOSECURE_CONFIG;
  return parseConfig(JSON.parse(readFileSync(abs, 'utf8')) as Record<string, unknown>, path.dirname(abs), implicit);
}

export function resolveDataDir(config: Config): string {
  return expandPath(process.env.OSMOSECURE_DATA_DIR ?? config.dataDir, config.configDir);
}
