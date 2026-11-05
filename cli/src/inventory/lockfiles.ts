import type { Component, Ecosystem } from '../types.js';

type Parsed = Pick<Component, 'ecosystem' | 'name' | 'version'>[];

function dedupe(items: Parsed): Parsed {
  const seen = new Set<string>();
  const out: Parsed = [];
  for (const i of items) {
    const k = `${i.ecosystem}\0${i.name}\0${i.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(i);
  }
  return out;
}

interface NpmLockV2 {
  packages?: Record<string, { version?: string; link?: boolean; dev?: boolean; name?: string }>;
  dependencies?: Record<string, { version?: string; dev?: boolean; dependencies?: Record<string, unknown> }>;
}

export function parsePackageLock(text: string, includeDev = true): Parsed {
  const lock = JSON.parse(text) as NpmLockV2;
  const out: Parsed = [];
  if (lock.packages) {
    for (const [key, pkg] of Object.entries(lock.packages)) {
      if (!key || pkg.link || !pkg.version) continue;
      if (!includeDev && pkg.dev) continue;
      const idx = key.lastIndexOf('node_modules/');
      const name = pkg.name ?? (idx >= 0 ? key.slice(idx + 'node_modules/'.length) : key);
      out.push({ ecosystem: 'npm', name: name.toLowerCase(), version: pkg.version });
    }
  } else if (lock.dependencies) {
    const walk = (deps: NpmLockV2['dependencies']) => {
      for (const [name, d] of Object.entries(deps ?? {})) {
        if (d.version && /^\d/.test(d.version) && (includeDev || !d.dev)) {
          out.push({ ecosystem: 'npm', name: name.toLowerCase(), version: d.version });
        }
        if (d.dependencies) walk(d.dependencies as NpmLockV2['dependencies']);
      }
    };
    walk(lock.dependencies);
  }
  return dedupe(out);
}

/** pnpm-lock.yaml: v6+ keys `name@1.2.3(peer)`, v5 keys `/name/1.2.3`. */
export function parsePnpmLock(text: string): Parsed {
  const out: Parsed = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line)) inPackages = false;
    if (!inPackages) continue;
    const m = /^ {2}['"]?\/?((?:@[^/@'"]+\/)?[^@/'"\s]+)@(\d[^(:'"\s]*)/.exec(line);
    if (m) {
      out.push({ ecosystem: 'npm', name: m[1].toLowerCase(), version: m[2] });
      continue;
    }
    const v5 = /^ {2}['"]?\/((?:@[^/]+\/)?[^/]+)\/(\d[^_:'"\s]*)/.exec(line);
    if (v5) out.push({ ecosystem: 'npm', name: v5[1].toLowerCase(), version: v5[2] });
  }
  return dedupe(out);
}

/** yarn.lock v1 and berry. */
export function parseYarnLock(text: string): Parsed {
  const out: Parsed = [];
  let currentName: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line) && line.trimEnd().endsWith(':') && !line.startsWith('#')) {
      const first = line.replace(/:$/, '').split(',')[0].trim().replace(/^["']|["']$/g, '');
      const at = first.indexOf('@', 1);
      currentName = at > 0 ? first.slice(0, at) : null;
      continue;
    }
    const v = /^\s+version:?\s+["']?([^"'\s]+)["']?/.exec(line);
    if (v && currentName) {
      out.push({ ecosystem: 'npm', name: currentName.toLowerCase(), version: v[1] });
      currentName = null;
    }
  }
  return dedupe(out);
}

export function parseComposerLock(text: string, includeDev = true): Parsed {
  const lock = JSON.parse(text) as {
    packages?: { name: string; version: string }[];
    'packages-dev'?: { name: string; version: string }[];
  };
  const list = [...(lock.packages ?? []), ...(includeDev ? (lock['packages-dev'] ?? []) : [])];
  return dedupe(
    list
      .filter((p) => p.name && p.version)
      .map((p) => ({ ecosystem: 'Packagist' as Ecosystem, name: p.name.toLowerCase(), version: p.version.replace(/^v/, '') })),
  );
}

export function parseGemfileLock(text: string): Parsed {
  const out: Parsed = [];
  let inSpecs = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s{2}specs:\s*$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (inSpecs && /^\S/.test(line)) inSpecs = false;
    if (!inSpecs) continue;
    const m = /^ {4}([A-Za-z0-9_.\-]+) \(([^)\s]+)\)\s*$/.exec(line);
    if (m) out.push({ ecosystem: 'RubyGems', name: m[1].toLowerCase(), version: m[2].replace(/-.*$/, '') });
  }
  return dedupe(out);
}

/** Only exact pins (==) are inventoried; ranges have no single installed version. */
export function parseRequirements(text: string): Parsed {
  const out: Parsed = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('#')[0].trim();
    const m = /^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)/.exec(line);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1].toLowerCase().replace(/_/g, '-'), version: m[2] });
  }
  return dedupe(out);
}

export interface LockfileKind {
  type: string;
  parse: (text: string, includeDev: boolean) => Parsed;
}

export function lockfileKind(basename: string): LockfileKind | null {
  if (basename === 'package-lock.json' || basename === 'npm-shrinkwrap.json')
    return { type: 'package-lock', parse: parsePackageLock };
  if (basename === 'pnpm-lock.yaml') return { type: 'pnpm-lock', parse: (t) => parsePnpmLock(t) };
  if (basename === 'yarn.lock') return { type: 'yarn-lock', parse: (t) => parseYarnLock(t) };
  if (basename === 'composer.lock') return { type: 'composer-lock', parse: parseComposerLock };
  if (basename === 'Gemfile.lock') return { type: 'gemfile-lock', parse: (t) => parseGemfileLock(t) };
  if (/^requirements.*\.txt$/.test(basename)) return { type: 'requirements', parse: (t) => parseRequirements(t) };
  return null;
}
