/**
 * Runtime smoke gate helpers for the fixer. Kept separate from fix.ts so the pipeline file only carries
 * the call sites. A smoke command is argv form (never a shell string) and only proves what it exercises.
 */

export type SmokeResult = 'pass' | 'fail' | 'not configured';

export interface SmokeReport {
  result: SmokeResult;
  command: string[] | null;
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
}

export function emptySmoke(): SmokeReport {
  return { result: 'not configured', command: null, exitCode: null, timedOut: false, durationMs: 0 };
}

/** Packages whose override can break startup (instrumentation hooks patch other modules on import). */
const INSTRUMENTATION_PATTERNS: RegExp[] = [
  /^@opentelemetry\//,
  /^@sentry\//,
  /^@sentry-internal\//,
  /^@prisma\/instrumentation$/,
  /^@datadog\//,
  /^dd-trace$/,
  /^newrelic$/,
  /^import-in-the-middle$/,
  /^require-in-the-middle$/,
  /^module-details-from-path$/,
  /^shimmer$/,
  /(^|[/-])instrumentation(-[a-z0-9-]+)?$/,
];

export function isInstrumentationPackage(name: string): boolean {
  return INSTRUMENTATION_PATTERNS.some((re) => re.test(name));
}

/** Short line for the report and approval output. Never includes environment values. */
export function describeSmoke(s: SmokeReport | undefined): string {
  if (!s || s.result === 'not configured') return 'not configured';
  const detail = `${s.command ? s.command.join(' ') + ', ' : ''}${s.timedOut ? 'timed out' : `exit ${s.exitCode}`}, ${s.durationMs} ms`;
  return `${s.result === 'pass' ? 'passed' : 'FAILED'} (${detail})`;
}
