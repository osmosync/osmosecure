import { normalizeProduct } from '../inventory/host.js';
import { branchOf, compareVersions, numericParts } from '../lib/version.js';
import type { Component } from '../types.js';
import { imageBasename } from './prefilter.js';
import type { TriageProduct } from './schema.js';

export type Verdict = 'affected' | 'unaffected' | 'needs-verification';

export interface Match {
  component: Component;
  verdict: Verdict;
  fixedVersion?: string;
  reason: string;
}

function inRange(v: string, r: TriageProduct['affectedRanges'][number]): boolean | null {
  if (r.introduced) {
    const c = compareVersions(v, r.introduced);
    if (c === null) return null;
    if (c < 0) return false;
  }
  if (r.fixed) {
    const c = compareVersions(v, r.fixed);
    if (c === null) return null;
    return c < 0;
  }
  if (r.lastAffected) {
    const c = compareVersions(v, r.lastAffected);
    if (c === null) return null;
    return c <= 0;
  }
  return r.introduced !== null || r.fixed !== null || r.lastAffected !== null ? true : null;
}

/** Version verdict for one installed version against a triaged product. Pure and deterministic. */
export function versionVerdict(installed: string, p: TriageProduct): { verdict: Verdict; fixedVersion?: string; reason: string } {
  const parts = numericParts(installed);
  if (!parts) return { verdict: 'needs-verification', reason: `non-numeric version "${installed}" (floating tag?)` };

  // Branch-aware check first: disclosures list one fix per supported branch.
  const branch = branchOf(installed);
  if (p.fixedVersions.length > 0) {
    if (branch) {
      const same = p.fixedVersions.find((f) => branchOf(f) === branch);
      if (same) {
        const c = compareVersions(installed, same);
        if (c === -1) return { verdict: 'affected', fixedVersion: same, reason: `${installed} is below fixed ${same} on branch ${branch}` };
        if (c !== null) return { verdict: 'unaffected', reason: `${installed} is at or above fixed ${same} on branch ${branch}` };
      }
    } else if (parts.length === 1) {
      const sameMajor = p.fixedVersions.find((f) => numericParts(f)?.[0] === parts[0]);
      if (sameMajor) {
        return { verdict: 'needs-verification', fixedVersion: sameMajor, reason: `only major ${parts[0]} known; fixed ${sameMajor} exists, check the running version` };
      }
    }
  }

  const verdicts = p.affectedRanges.map((r) => inRange(installed, r));
  if (verdicts.some((v) => v === true)) {
    const fixed = p.affectedRanges.find((r, i) => verdicts[i] && r.fixed)?.fixed ?? undefined;
    return { verdict: 'affected', fixedVersion: fixed, reason: `${installed} falls in a stated affected range` };
  }
  if (verdicts.length > 0 && verdicts.every((v) => v === false)) {
    return { verdict: 'unaffected', reason: `${installed} is outside every stated affected range` };
  }
  return { verdict: 'needs-verification', reason: `branch ${branch ?? installed} not covered by the stated versions` };
}

function nameMatches(c: Component, p: TriageProduct): boolean {
  const want = normalizeProduct(p.name);
  if (c.kind === 'runtime') return c.name === want;
  if (c.kind === 'image') return normalizeProduct(imageBasename(c.name)) === want;
  // library package: exact name, and ecosystem must agree when the model stated one
  if (c.name !== p.name.toLowerCase()) return false;
  return p.ecosystem === 'unknown' || p.ecosystem === c.ecosystem;
}

/** Matches triaged products against the inventory, including host runtimes and container images. */
export function matchTriage(products: TriageProduct[], components: Component[]): Match[] {
  const matches: Match[] = [];
  for (const p of products) {
    for (const c of components) {
      if (!nameMatches(c, p)) continue;
      const v = versionVerdict(c.version, p);
      if (v.verdict === 'unaffected') continue;
      let { verdict, reason } = v;
      if (verdict === 'affected' && c.distroPackaged) {
        verdict = 'needs-verification';
        reason += '; distro package, backported fixes are likely so check the vendor notice (USN/DSA)';
      }
      if (verdict === 'affected' && c.kind === 'image') {
        verdict = 'needs-verification';
        reason += '; image tag only, confirm the running digest';
      }
      matches.push({ component: c, verdict, fixedVersion: v.fixedVersion, reason });
    }
  }
  return matches;
}
