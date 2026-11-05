import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { expandPath, type Config } from '../config.js';
import type { Component, Inventory, Logger } from '../types.js';
import { parseComposeImages } from './compose.js';
import { loadHostDumps } from './host.js';
import { loadInventoryFile } from './file.js';
import { lockfileKind } from './lockfiles.js';

const COMPOSE_NAME = /^(docker-)?compose(\.[\w.-]+)?\.ya?ml$/;

function* walk(root: string, depth: number, skip: Set<string>): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return;
  }
  for (const name of entries) {
    const full = path.join(root, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (depth > 0 && !skip.has(name)) yield* walk(full, depth - 1, skip);
    } else if (st.isFile()) {
      yield full;
    }
  }
}

export function buildInventory(config: Config, dataDir: string, log: Logger): Inventory {
  const components: Component[] = [];
  const manifests: Inventory['manifests'] = [];
  const errors: string[] = [];

  for (const project of config.projects) {
    const root = expandPath(project.root, config.configDir);
    if (!existsSync(root)) {
      const msg = `project ${project.id}: root not found (${root})`;
      if (project.optional) log.info(msg);
      else errors.push(msg);
      continue;
    }
    for (const file of walk(root, project.maxDepth, new Set(project.skipDirs))) {
      const base = path.basename(file);
      const rel = path.relative(root, file);
      try {
        const kind = lockfileKind(base);
        if (kind) {
          const parsed = kind.parse(readFileSync(file, 'utf8'), config.scan.includeDevDependencies);
          for (const p of parsed) {
            components.push({ ...p, origin: rel, project: project.id, kind: 'package' });
          }
          manifests.push({ project: project.id, path: rel, type: kind.type, count: parsed.length });
        } else if (COMPOSE_NAME.test(base)) {
          const images = parseComposeImages(readFileSync(file, 'utf8'));
          for (const img of images) {
            components.push({
              ecosystem: 'Docker',
              name: img.repository,
              version: img.tag,
              origin: rel,
              project: project.id,
              kind: 'image',
            });
          }
          manifests.push({ project: project.id, path: rel, type: 'compose', count: images.length });
        }
      } catch (err) {
        errors.push(`${project.id}:${rel}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  for (const f of config.inventoryFiles) {
    const file = expandPath(f, config.configDir);
    try {
      const comps = loadInventoryFile(readFileSync(file, 'utf8'));
      components.push(...comps);
      manifests.push({ project: comps[0]?.project ?? 'inventory-file', path: f, type: 'inventory-file', count: comps.length });
    } catch (err) {
      errors.push(`inventory file ${f}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (config.localRuntimes.includeNode) {
    components.push({
      ecosystem: 'Host',
      name: 'node',
      version: process.version.replace(/^v/, ''),
      origin: 'local:process',
      project: 'host:local',
      kind: 'runtime',
    });
  }

  const hostIds = config.hosts.map((h) => h.id);
  const dumps = loadHostDumps(dataDir, hostIds);
  components.push(...dumps.components);
  for (const host of dumps.missing) log.info(`no second-pass host dump for ${host} (see README: host collection)`);

  return { generatedAt: new Date().toISOString(), components, manifests, errors };
}

export function summarizeInventory(inv: Inventory): string {
  const byEco = new Map<string, number>();
  for (const c of inv.components) byEco.set(c.ecosystem, (byEco.get(c.ecosystem) ?? 0) + 1);
  return [...byEco.entries()].map(([k, v]) => `${k}=${v}`).join(' ');
}
