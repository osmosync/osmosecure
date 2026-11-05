import { scrubSecrets } from '../triage/scrub.js';
import type { Logger } from '../types.js';

const SECRET_KEYS = /(key|token|secret|authorization|password)/i;

function redact(extra?: Record<string, unknown>): string {
  if (!extra) return '';
  const safe: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(extra)) safe[k] = SECRET_KEYS.test(k) ? '[redacted]' : typeof v === 'string' ? scrubSecrets(v) : v;
  return ' ' + JSON.stringify(safe);
}

export function createLogger(quiet = false): Logger {
  const line = (level: string, msg: string, extra?: Record<string, unknown>) =>
    console.error(scrubSecrets(`${new Date().toISOString()} ${level} ${msg}${redact(extra)}`));
  return {
    info: (m, e) => {
      if (!quiet) line('info', m, e);
    },
    warn: (m, e) => line('warn', m, e),
    error: (m, e) => line('error', m, e),
  };
}

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };
