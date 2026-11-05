import type { OsvVuln } from '../scan/osv.js';
import type { FeedItem } from '../types.js';
import { extractCves, lookbackStart, type FeedContext, type FeedResult } from './types.js';

/** Parses the head of an OSV `modified_id.csv` (newest first): `2026-10-22T01:02:03Z,GHSA-xxxx`. */
export function parseModifiedCsv(text: string, since: Date, truncated: boolean): { id: string; modified: string }[] {
  const lines = text.split(/\r?\n/);
  if (truncated) lines.pop(); // last line may be cut mid-record
  const out: { id: string; modified: string }[] = [];
  for (const line of lines) {
    const [modified, id] = line.split(',');
    if (!modified || !id) continue;
    if (Date.parse(modified) < since.getTime()) break; // sorted descending
    out.push({ id: id.trim(), modified });
  }
  return out;
}

export function vulnToItem(v: OsvVuln, inventoryNames: Map<string, Set<string>>): FeedItem | null {
  const packages = (v.affected ?? [])
    .map((a) => ({ ecosystem: a.package?.ecosystem ?? '', name: (a.package?.name ?? '').toLowerCase() }))
    .filter((p) => p.name && inventoryNames.get(p.ecosystem)?.has(p.name));
  if (packages.length === 0) return null;
  const all = [v.id, ...(v.aliases ?? [])];
  return {
    source: 'osv',
    id: v.id,
    title: (v.summary ?? v.id).slice(0, 200),
    text: '',
    url: `https://osv.dev/vulnerability/${v.id}`,
    cves: all.filter((x) => x.startsWith('CVE-')),
    productHints: packages.map((p) => p.name),
    packages,
  };
}

export async function collectOsv(ctx: FeedContext): Promise<FeedResult> {
  const cfg = ctx.config.feeds.osv;
  const since = lookbackStart(ctx, 'osv');
  const items: FeedItem[] = [];
  let newest = since.toISOString();
  try {
    let budget = cfg.maxIdsPerRun;
    for (const eco of cfg.ecosystems) {
      if (!ctx.inventoryNames.get(eco)?.size) continue;
      // Ask only for the head of the file: GCS honours Range and the file is sorted newest first.
      const res = await ctx.http.request(
        `${cfg.baseUrl}/${eco}/modified_id.csv`,
        { headers: { range: 'bytes=0-262143' } },
        { minIntervalMs: 1000 },
      );
      const rows = parseModifiedCsv(res.body, since, res.status === 206);
      for (const row of rows) {
        if (row.modified > newest) newest = row.modified;
        if (budget-- <= 0) break;
        if (ctx.state.isSeen('osv', row.id)) continue;
        try {
          const { data } = await ctx.http.json<OsvVuln>(`${cfg.apiUrl}/v1/vulns/${encodeURIComponent(row.id)}`, {}, { minIntervalMs: 100 });
          const item = vulnToItem(data, ctx.inventoryNames);
          if (item) items.push(item);
          else ctx.state.markSeen('osv', row.id, ctx.now); // not relevant to us
        } catch (err) {
          ctx.log.warn('osv detail failed', { id: row.id, error: err instanceof Error ? err.message : String(err) });
        }
      }
    }
    ctx.state.state.cursors.osv = newest;
    return { source: 'osv', items };
  } catch (err) {
    return { source: 'osv', items, error: err instanceof Error ? err.message : String(err) };
  }
}

export { extractCves };
