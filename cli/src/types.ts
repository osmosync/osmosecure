export type Ecosystem = 'npm' | 'Packagist' | 'RubyGems' | 'PyPI' | 'Docker' | 'Host';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type Tier = 'page' | 'alert' | 'digest' | 'log';

/** One installed thing: a library, a container image, or a host package/runtime. */
export interface Component {
  ecosystem: Ecosystem;
  /** Lowercased package name, image repository, or normalized host product. */
  name: string;
  version: string;
  /** Where we saw it: lockfile path relative to the project root, compose file, or host name. */
  origin: string;
  project: string;
  kind: 'package' | 'image' | 'runtime';
  /** True when version comes from a distro package (backports make upstream version compare unreliable). */
  distroPackaged?: boolean;
  /** Raw package name when it differs from `name` (for example php8.3-cli). */
  rawName?: string;
}

export interface Inventory {
  generatedAt: string;
  components: Component[];
  /** Lockfiles and compose files that were parsed. */
  manifests: { project: string; path: string; type: string; count: number }[];
  errors: string[];
}

export interface FixInfo {
  fixedVersion?: string;
}

export interface Finding {
  /** Stable dedupe key. */
  key: string;
  advisoryId: string;
  aliases: string[];
  cves: string[];
  title: string;
  severity: Severity;
  source: string;
  url?: string;
  component: Component;
  fixedVersion?: string;
  /** deterministic = lockfile/OSV match; llm = triaged free text; the latter may be unverified */
  basis: 'deterministic' | 'llm-triage';
  verdict: 'affected' | 'needs-verification';
  kev: boolean;
  epss?: number;
  score: number;
  tier: Tier;
  note?: string;
}

export interface FeedItem {
  source: string;
  id: string;
  title: string;
  /** Untrusted free text. */
  text: string;
  url?: string;
  publishedAt?: string;
  cves: string[];
  /** Product hints from structured sources (KEV vendor/product, NVD CPE). Used for prefilter only. */
  productHints: string[];
  /** Structured package names from OSV/GHSA, used to trigger a rescan. */
  packages?: { ecosystem: string; name: string }[];
  kev?: boolean;
  severity?: Severity;
}

export interface Logger {
  info(msg: string, extra?: Record<string, unknown>): void;
  warn(msg: string, extra?: Record<string, unknown>): void;
  error(msg: string, extra?: Record<string, unknown>): void;
}

/** A finding before KEV/EPSS enrichment and ranking. */
export type Candidate = Omit<Finding, 'score' | 'tier' | 'kev' | 'epss'>;
