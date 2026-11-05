import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { cvss3BaseScore, severityFromLabel, severityFromScore } from '../lib/cvss.js';
import type { Candidate, Component, Severity } from '../types.js';

const run = promisify(execFile);

export async function osvScannerAvailable(bin = 'osv-scanner'): Promise<boolean> {
  try {
    await run(bin, ['--version'], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

interface ScannerJson {
  results?: {
    source?: { path?: string };
    packages?: {
      package: { name: string; version: string; ecosystem: string };
      vulnerabilities?: {
        id: string;
        aliases?: string[];
        summary?: string;
        severity?: { type: string; score: string }[];
        database_specific?: { severity?: string };
      }[];
    }[];
  }[];
}

/** Maps osv-scanner `--format json` output onto inventory components. */
export function parseOsvScannerJson(json: ScannerJson, components: Component[]): Candidate[] {
  const index = new Map<string, Component[]>();
  for (const c of components) {
    const k = `${c.ecosystem}\0${c.name}\0${c.version}`;
    index.set(k, [...(index.get(k) ?? []), c]);
  }
  const out: Candidate[] = [];
  for (const res of json.results ?? []) {
    for (const p of res.packages ?? []) {
      const matches = index.get(`${p.package.ecosystem}\0${p.package.name.toLowerCase()}\0${p.package.version}`) ?? [];
      for (const v of p.vulnerabilities ?? []) {
        let severity: Severity = severityFromLabel(v.database_specific?.severity);
        for (const s of v.severity ?? []) {
          const score = s.type?.startsWith('CVSS_V3') ? cvss3BaseScore(s.score) : null;
          if (score !== null) severity = severityFromScore(score);
        }
        const aliases = (v.aliases ?? []).filter((a) => a !== v.id);
        for (const c of matches) {
          out.push({
            key: `${v.id}|${c.project}|${c.ecosystem}:${c.name}@${c.version}`,
            advisoryId: v.id,
            aliases,
            cves: [v.id, ...aliases].filter((x) => x.startsWith('CVE-')),
            title: (v.summary ?? v.id).slice(0, 200),
            severity,
            source: 'osv-scanner',
            url: `https://osv.dev/vulnerability/${v.id}`,
            component: c,
            basis: 'deterministic',
            verdict: 'affected',
          });
        }
      }
    }
  }
  return out;
}

/**
 * Runs osv-scanner against a synthetic lockfile list is out of scope for v1; we pass project roots.
 * Fixed versions are not in osv-scanner's JSON, so candidates from this path carry no fixedVersion
 * (remediation then requires approval). The API path fills fixedVersion.
 */
export async function scanWithOsvScanner(roots: string[], components: Component[], bin = 'osv-scanner'): Promise<Candidate[]> {
  const out: Candidate[] = [];
  for (const root of roots) {
    try {
      const { stdout } = await run(bin, ['--format', 'json', '-r', root], { timeout: 600_000, maxBuffer: 256 * 1024 * 1024 });
      out.push(...parseOsvScannerJson(JSON.parse(stdout) as ScannerJson, components));
    } catch (err) {
      // osv-scanner exits 1 when vulnerabilities are found; stdout still holds the report.
      const e = err as { code?: number; stdout?: string };
      if (e.code === 1 && e.stdout) out.push(...parseOsvScannerJson(JSON.parse(e.stdout) as ScannerJson, components));
      else throw err;
    }
  }
  return out;
}
