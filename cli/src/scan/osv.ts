import { cvss3BaseScore, severityFromLabel, severityFromScore } from '../lib/cvss.js';
import { compareVersions } from '../lib/version.js';
import type { HttpClient } from '../http.js';
import type { Candidate, Component, Logger, Severity } from '../types.js';

export interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { type: string; events: Record<string, string>[] }[];
  }[];
  references?: { url: string }[];
}

const SCANNABLE = new Set(['npm', 'Packagist', 'RubyGems', 'PyPI']);
const BATCH = 1000;

export function scannable(c: Component): boolean {
  return SCANNABLE.has(c.ecosystem) && c.kind === 'package';
}

export function osvSeverity(v: OsvVuln): Severity {
  for (const s of v.severity ?? []) {
    if (s.type?.startsWith('CVSS_V3')) {
      const score = cvss3BaseScore(s.score);
      if (score !== null) return severityFromScore(score);
    }
  }
  return severityFromLabel(v.database_specific?.severity);
}

/** Smallest fixed version above `current` for this package, across all ranges. */
export function osvFixedVersion(v: OsvVuln, c: Pick<Component, 'ecosystem' | 'name' | 'version'>): string | undefined {
  let best: string | undefined;
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== c.ecosystem || a.package?.name?.toLowerCase() !== c.name) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) {
        const fixed = e.fixed;
        if (!fixed) continue;
        if (compareVersions(fixed, c.version) !== 1) continue;
        if (!best || compareVersions(fixed, best) === -1) best = fixed;
      }
    }
  }
  return best;
}

export function candidateFromVuln(v: OsvVuln, c: Component, source: string): Candidate {
  const aliases = (v.aliases ?? []).filter((a) => a !== v.id);
  const all = [v.id, ...aliases];
  return {
    key: `${v.id}|${c.project}|${c.ecosystem}:${c.name}@${c.version}`,
    advisoryId: v.id,
    aliases,
    cves: all.filter((x) => x.startsWith('CVE-')),
    title: (v.summary ?? v.id).slice(0, 200),
    severity: osvSeverity(v),
    source,
    url: `https://osv.dev/vulnerability/${v.id}`,
    component: c,
    fixedVersion: osvFixedVersion(v, c),
    basis: 'deterministic',
    verdict: 'affected',
  };
}

export class OsvApi {
  constructor(
    private readonly http: HttpClient,
    private readonly apiUrl: string,
    private readonly log: Logger,
  ) {}

  /** Returns component index -> vuln ids affecting it. */
  async queryBatch(components: Component[]): Promise<Map<number, string[]>> {
    const result = new Map<number, string[]>();
    for (let start = 0; start < components.length; start += BATCH) {
      const slice = components.slice(start, start + BATCH);
      let queries = slice.map((c) => ({ package: { name: c.name, ecosystem: c.ecosystem }, version: c.version }));
      let idx = slice.map((_, i) => start + i);
      // Follow next_page_token until every query is drained.
      for (let round = 0; round < 10 && queries.length > 0; round++) {
        const { data } = await this.http.json<{ results: { vulns?: { id: string }[]; next_page_token?: string }[] }>(
          `${this.apiUrl}/v1/querybatch`,
          { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries }) },
          { minIntervalMs: 300, timeoutMs: 60_000 },
        );
        const nextQueries: typeof queries = [];
        const nextIdx: number[] = [];
        data.results.forEach((r, i) => {
          const gi = idx[i];
          if (r.vulns?.length) result.set(gi, [...(result.get(gi) ?? []), ...r.vulns.map((x) => x.id)]);
          if (r.next_page_token) {
            nextQueries.push({ ...queries[i], page_token: r.next_page_token } as (typeof queries)[number]);
            nextIdx.push(gi);
          }
        });
        queries = nextQueries;
        idx = nextIdx;
      }
    }
    this.log.info('osv querybatch complete', { components: components.length, withVulns: result.size });
    return result;
  }

  async getVuln(id: string): Promise<OsvVuln> {
    const { data } = await this.http.json<OsvVuln>(`${this.apiUrl}/v1/vulns/${encodeURIComponent(id)}`, {}, {
      minIntervalMs: 100,
      cache: true,
    });
    return data;
  }
}

/** API-fallback scan of lockfile packages. */
export async function scanWithOsvApi(
  api: OsvApi,
  components: Component[],
  maxDetailFetch: number,
  log: Logger,
): Promise<{ candidates: Candidate[]; skippedDetails: number }> {
  const targets = components.filter(scannable);
  const hits = await api.queryBatch(targets);
  const ids = [...new Set([...hits.values()].flat())];
  const details = new Map<string, OsvVuln>();
  let fetched = 0;
  let skipped = 0;
  for (const id of ids) {
    if (fetched >= maxDetailFetch) {
      skipped++;
      continue;
    }
    try {
      details.set(id, await api.getVuln(id));
      fetched++;
    } catch (err) {
      log.warn('osv vuln fetch failed', { id, error: err instanceof Error ? err.message : String(err) });
    }
  }
  const candidates: Candidate[] = [];
  for (const [i, vulnIds] of hits) {
    const c = targets[i];
    for (const id of new Set(vulnIds)) {
      const v = details.get(id);
      if (v) candidates.push(candidateFromVuln(v, c, 'osv-api'));
    }
  }
  return { candidates, skippedDetails: skipped };
}
