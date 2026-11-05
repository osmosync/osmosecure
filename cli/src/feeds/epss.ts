import type { FeedContext } from './types.js';

const TTL_MS = 20 * 3_600_000;

/** Refreshes EPSS scores for the given CVEs into state. Public FIRST.org API, batched. */
export async function refreshEpss(ctx: FeedContext, cves: string[]): Promise<{ fetched: number; error?: string }> {
  const cfg = ctx.config.feeds.epss;
  const stale = [...new Set(cves)].filter((c) => {
    const e = ctx.state.state.epss[c];
    return !e || ctx.now.getTime() - Date.parse(e.fetchedAt) > TTL_MS;
  });
  let fetched = 0;
  try {
    for (let i = 0; i < stale.length; i += cfg.batchSize) {
      const batch = stale.slice(i, i + cfg.batchSize);
      const { data } = await ctx.http.json<{ data?: { cve: string; epss: string; percentile: string }[] }>(
        `${cfg.url}?cve=${batch.join(',')}`,
        {},
        { minIntervalMs: 1000 },
      );
      for (const row of data.data ?? []) {
        ctx.state.state.epss[row.cve] = {
          score: Number(row.epss),
          percentile: Number(row.percentile),
          fetchedAt: ctx.now.toISOString(),
        };
        fetched++;
      }
      // CVEs EPSS does not know get a zero entry so we do not re-ask every run.
      for (const c of batch) {
        if (!ctx.state.state.epss[c]) {
          ctx.state.state.epss[c] = { score: 0, percentile: 0, fetchedAt: ctx.now.toISOString() };
        }
      }
    }
    return { fetched };
  } catch (err) {
    return { fetched, error: err instanceof Error ? err.message : String(err) };
  }
}
