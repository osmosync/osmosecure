import type { Severity } from '../types.js';

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function roundUp(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.x base score from a vector string, or null if it cannot be parsed. */
export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));
  const scopeChanged = m.S === 'C';
  const pr: Record<string, number> = scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  if (!(m.AV in AV && m.AC in AC && m.UI in UI && m.PR in pr && m.C in CIA && m.I in CIA && m.A in CIA)) return null;
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * AV[m.AV] * AC[m.AC] * pr[m.PR] * UI[m.UI];
  if (impact <= 0) return 0;
  return roundUp(Math.min(scopeChanged ? 1.08 * (impact + expl) : impact + expl, 10));
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

export function severityFromLabel(label: string | undefined): Severity {
  switch ((label ?? '').toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
    case 'important':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'unknown';
  }
}
