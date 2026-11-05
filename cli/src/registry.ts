import type { HttpClient } from './http.js';
import { isName, isVersion } from './tokens.js';

/**
 * npm registry metadata, used only to choose versions and to build trusted links. Everything read from a registry
 * document is shape-checked before use; descriptions, READMEs and changelog text are never read at all.
 */

export interface RepoRef {
  host: 'github.com' | 'gitlab.com';
  /** owner/repo (GitLab may have nested groups), characters validated. */
  path: string;
}

const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

/** Accepts the usual `repository` spellings and returns a github.com or gitlab.com reference, or null. */
export function normalizeRepo(raw: unknown): RepoRef | null {
  let url = typeof raw === 'string' ? raw : raw && typeof raw === 'object' && typeof (raw as { url?: unknown }).url === 'string' ? (raw as { url: string }).url : '';
  url = url.trim();
  if (!url || url.length > 300) return null;
  let host = '';
  let p = '';
  const short = /^(github|gitlab):([^/\s]+\/[^/\s]+)$/.exec(url);
  const scp = /^git@([^:/\s]+):(.+)$/.exec(url);
  if (short) {
    host = `${short[1]}.com`;
    p = short[2];
  } else if (scp) {
    host = scp[1].toLowerCase();
    p = scp[2];
  } else if (/^[^/\s:]+\/[^/\s:]+$/.test(url)) {
    host = 'github.com'; // npm shorthand "owner/repo"
    p = url;
  } else {
    try {
      const u = new URL(url.replace(/^git\+/, ''));
      if (!['https:', 'http:', 'git:', 'ssh:'].includes(u.protocol) || u.username.includes(':') || u.search || u.hash) return null;
      host = u.hostname.toLowerCase();
      p = u.pathname.replace(/^\//, '');
    } catch {
      return null;
    }
  }
  if (host !== 'github.com' && host !== 'gitlab.com') return null;
  p = p.replace(/\.git$/, '').replace(/\/+$/, '');
  const parts = p.split('/');
  if (parts.length < 2 || (host === 'github.com' && parts.length !== 2) || parts.length > 6 || !parts.every((s) => SEGMENT_RE.test(s) && s !== '.' && s !== '..')) return null;
  return { host, path: parts.join('/') };
}

/** Links for a PR body: the package's own repository releases page and the registry page. Built from validated parts only. */
export function releaseLinks(name: string, version: string, repo: RepoRef | null): string[] {
  const links: string[] = [];
  if (repo) links.push(repo.host === 'github.com' ? `https://github.com/${repo.path}/releases` : `https://gitlab.com/${repo.path}/-/releases`);
  if (isName(name) && isVersion(version)) links.push(`https://www.npmjs.com/package/${name}/v/${version}`);
  return links;
}

export const STABLE_RE = /^\d+\.\d+\.\d+$/;

export interface Packument {
  /** Stable (x.y.z) versions only, deprecated ones removed. */
  versions: string[];
  /** Publish time by version, only when the full document was requested. */
  time: Record<string, string>;
}

export const npmDocPath = (name: string): string => (name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name));

export async function fetchPackument(http: HttpClient, base: string, name: string, withTime: boolean): Promise<Packument> {
  if (!isName(name)) throw new Error('invalid package name');
  const headers: Record<string, string> = withTime ? {} : { accept: 'application/vnd.npm.install-v1+json' };
  const { data } = await http.json<{ versions?: Record<string, { deprecated?: unknown }>; time?: Record<string, unknown> }>(`${base.replace(/\/$/, '')}/${npmDocPath(name)}`, {}, { minIntervalMs: 50, headers, maxBytes: 32 * 1024 * 1024 });
  const versions = Object.entries(data.versions ?? {})
    .filter(([v, m]) => STABLE_RE.test(v) && !(m && m.deprecated))
    .map(([v]) => v);
  const time: Record<string, string> = {};
  if (withTime) for (const [v, t] of Object.entries(data.time ?? {})) if (STABLE_RE.test(v) && typeof t === 'string' && !Number.isNaN(Date.parse(t))) time[v] = t;
  return { versions, time };
}

export interface VersionMeta {
  /** Raw SPDX expression as declared, or null. */
  license: string | null;
  repo: RepoRef | null;
}

export async function fetchVersionMeta(http: HttpClient, base: string, name: string, version: string): Promise<VersionMeta> {
  if (!isName(name) || !isVersion(version)) throw new Error('invalid package name or version');
  const { data } = await http.json<{ license?: unknown; repository?: unknown }>(`${base.replace(/\/$/, '')}/${npmDocPath(name)}/${encodeURIComponent(version)}`, {}, { minIntervalMs: 50 });
  const lic = typeof data.license === 'string' && data.license.length <= 200 ? data.license.trim() : null;
  return { license: lic, repo: normalizeRepo(data.repository) };
}
