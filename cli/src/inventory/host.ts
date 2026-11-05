import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { Component } from '../types.js';

/** Product names the matcher and host inventory agree on. */
export function normalizeProduct(raw: string): string {
  const n = raw.toLowerCase().trim();
  if (/^php\d*(\.\d+)?(-|$)/.test(n)) return 'php';
  if (n === 'openssl' || /^libssl\d/.test(n)) return 'openssl';
  if (/^nginx(-|$)/.test(n) || n === 'nginx') return 'nginx';
  if (n === 'nodejs' || n === 'node') return 'node';
  if (/^postgres(ql)?(-\d+)?$/.test(n) || /^postgresql-(client-)?\d+/.test(n)) return 'postgres';
  if (n === 'docker-ce' || n === 'docker.io') return 'docker';
  if (n === 'containerd.io' || n === 'containerd') return 'containerd';
  if (n === 'redis-server' || n === 'redis') return 'redis';
  if (n === 'openssh-server') return 'openssh';
  return n;
}

const WATCHLIST = new Set(['php', 'openssl', 'nginx', 'node', 'postgres', 'docker', 'containerd', 'redis', 'openssh']);

/**
 * Parses the output of:
 *   dpkg-query -W -f='${Package}\t${Version}\n'
 * Only watchlisted runtimes are kept; the rest of the distro package set is a documented TODO
 * (OSV Debian/Ubuntu ecosystem queries).
 */
export function parseDpkgTsv(text: string, host: string): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const [pkg, version] = line.split('\t');
    if (!pkg || !version) continue;
    const name = normalizeProduct(pkg);
    if (!WATCHLIST.has(name)) continue;
    // Skip dev/doc/common sub-packages that share a version with the main package.
    if (/-(dev|doc|common|dbg)$/.test(pkg) && name !== 'node') continue;
    const key = `${name}\0${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      ecosystem: 'Host',
      name,
      rawName: pkg,
      version,
      origin: `${host}:dpkg`,
      project: `host:${host}`,
      kind: 'runtime',
      distroPackaged: true,
    });
  }
  return out;
}

/** Parses `docker ps --format '{{.Image}}\t{{.ID}}'` style output: image ref, optional digest/id. */
export function parseImagesTsv(text: string, host: string): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const [ref, digest] = line.split('\t');
    if (!ref?.trim()) continue;
    const clean = ref.trim().replace(/@sha256:[a-f0-9]+$/, '');
    const slash = clean.lastIndexOf('/');
    const colon = clean.indexOf(':', slash + 1);
    const repository = (colon >= 0 ? clean.slice(0, colon) : clean).toLowerCase();
    const tag = colon >= 0 ? clean.slice(colon + 1) : 'latest';
    const key = `${repository}:${tag}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      ecosystem: 'Docker',
      name: repository,
      version: tag,
      origin: `${host}:docker${digest ? `@${digest.trim()}` : ''}`,
      project: `host:${host}`,
      kind: 'image',
    });
  }
  return out;
}

/** Loads second-pass dumps from <dataDir>/host/<host>/{dpkg.tsv,images.tsv} if present. */
export function loadHostDumps(dataDir: string, hosts: string[]): { components: Component[]; missing: string[] } {
  const components: Component[] = [];
  const missing: string[] = [];
  for (const host of hosts) {
    const dir = path.join(dataDir, 'host', host);
    const dpkg = path.join(dir, 'dpkg.tsv');
    const images = path.join(dir, 'images.tsv');
    if (!existsSync(dpkg) && !existsSync(images)) {
      missing.push(host);
      continue;
    }
    if (existsSync(dpkg)) components.push(...parseDpkgTsv(readFileSync(dpkg, 'utf8'), host));
    if (existsSync(images)) components.push(...parseImagesTsv(readFileSync(images, 'utf8'), host));
  }
  return { components, missing };
}
