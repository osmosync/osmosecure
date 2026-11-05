/**
 * Strict token validators for text that is written to a third party (Git host issues, PR bodies).
 * Anything that fails is dropped, never escaped: advisory titles and other free text are not "tokens".
 */
import type { Finding, Severity } from './types.js';

const NAME_RE = /^[A-Za-z0-9@][A-Za-z0-9@._+/-]{0,127}$/;
const VERSION_RE = /^[0-9][0-9A-Za-z.+_~:-]{0,63}$/;
const ADVISORY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/;
const PATH_RE = /^[A-Za-z0-9._/-]{1,200}$/;
const ECOSYSTEMS = new Set(['npm', 'Packagist', 'RubyGems', 'PyPI', 'Docker', 'Host']);
const SEVERITIES = new Set<Severity>(['critical', 'high', 'medium', 'low', 'unknown']);

export const isName = (s: unknown): s is string => typeof s === 'string' && NAME_RE.test(s) && !s.includes('..');
export const isVersion = (s: unknown): s is string => typeof s === 'string' && VERSION_RE.test(s);
export const isAdvisoryId = (s: unknown): s is string => typeof s === 'string' && ADVISORY_RE.test(s);
export const isRelPath = (s: unknown): s is string => typeof s === 'string' && PATH_RE.test(s) && !s.split('/').includes('..') && !s.startsWith('/');

/** The only fields of a finding that may reach a Git host issue, all validated. null when a required one fails. */
export interface IssueTokens {
  name: string;
  version: string;
  ecosystem: string;
  advisoryId: string;
  severity: Severity;
  fixedVersion: string | null;
  kev: boolean;
  verdict: 'affected' | 'needs-verification';
  project: string;
  origin: string | null;
}

export function issueTokens(f: Finding): IssueTokens | null {
  const c = f.component;
  if (!isName(c.name) || !isVersion(c.version) || !ECOSYSTEMS.has(c.ecosystem) || !isAdvisoryId(f.advisoryId)) return null;
  if (!SEVERITIES.has(f.severity)) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(c.project)) return null;
  return {
    name: c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    advisoryId: f.advisoryId,
    severity: f.severity,
    fixedVersion: isVersion(f.fixedVersion) ? f.fixedVersion : null,
    kev: f.kev === true,
    verdict: f.verdict === 'needs-verification' ? 'needs-verification' : 'affected',
    project: c.project,
    origin: isRelPath(c.origin) ? c.origin : null,
  };
}
