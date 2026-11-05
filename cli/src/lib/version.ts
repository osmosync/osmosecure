/**
 * Loose version comparison good enough for upstream release numbers.
 * Handles Debian epochs (1:2.3), revisions (-0ubuntu1), tildes and suffixes by comparing
 * only the leading dotted-numeric part. Callers must treat distro versions as approximate.
 */
export function numericParts(version: string): number[] | null {
  const m = /^[vV]?(?:\d+:)?(\d+(?:\.\d+)*)/.exec(version.trim());
  if (!m) return null;
  return m[1].split('.').map((n) => Number.parseInt(n, 10));
}

export function compareVersions(a: string, b: string): number | null {
  const pa = numericParts(a);
  const pb = numericParts(b);
  if (!pa || !pb) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** major.minor branch key, for example "8.3" from 8.3.6-0ubuntu1. */
export function branchOf(version: string): string | null {
  const p = numericParts(version);
  if (!p || p.length < 2) return null;
  return `${p[0]}.${p[1]}`;
}

export type BumpClass = 'patch' | 'minor' | 'major' | 'unknown';

/** Classify the jump from current to fixed. patch = same major.minor, fixed strictly newer. */
export function bumpClass(current: string, fixed: string): BumpClass {
  const a = numericParts(current);
  const b = numericParts(fixed);
  if (!a || !b) return 'unknown';
  if (compareVersions(current, fixed) !== -1) return 'unknown';
  if (a[0] !== b[0]) return 'major';
  // 0.x semver: a minor bump may break
  if (a[0] === 0 && (a[1] ?? 0) !== (b[1] ?? 0)) return 'major';
  if ((a[1] ?? 0) !== (b[1] ?? 0)) return 'minor';
  return 'patch';
}
