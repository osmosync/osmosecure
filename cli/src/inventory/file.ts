import { z } from 'zod';
import type { Component, Ecosystem } from '../types.js';
import { normalizeProduct } from './host.js';

/** Mirrors skill/inventory-schema.json (the same file the skill validators check). */
const assetSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(['lockfile_package', 'container_image', 'host_runtime', 'os_package']),
  name: z.string().min(1),
  version: z.string().min(1),
  ecosystem: z.string().optional(),
  distro: z.string().optional(),
  distro_release: z.string().optional(),
  digest: z.string().optional(),
  location: z.string().min(1),
  detected_by: z.string().min(1),
  internet_exposed: z.boolean().optional(),
  notes: z.string().optional(),
});

const inventorySchema = z.object({
  schema_version: z.literal(1),
  generated_at: z.string(),
  owner: z.string().min(1),
  assets: z.array(assetSchema).min(1),
});

const PACKAGE_ECOSYSTEMS = new Set(['npm', 'Packagist', 'RubyGems', 'PyPI']);

/**
 * Turns a skill-format inventory file into components. This is how host runtimes (php, openssl,
 * nginx, node, postgres) and image tags enter the pipeline when no lockfile describes them.
 */
export function loadInventoryFile(text: string): Component[] {
  const inv = inventorySchema.parse(JSON.parse(text));
  const project = `inventory:${inv.owner}`;
  return inv.assets.map((a): Component => {
    if (a.kind === 'lockfile_package') {
      if (!a.ecosystem || !PACKAGE_ECOSYSTEMS.has(a.ecosystem)) {
        throw new Error(`asset ${a.id}: lockfile_package needs ecosystem in ${[...PACKAGE_ECOSYSTEMS].join(', ')}`);
      }
      return { ecosystem: a.ecosystem as Ecosystem, name: a.name.toLowerCase(), version: a.version, origin: a.location, project, kind: 'package' };
    }
    if (a.kind === 'container_image') {
      return { ecosystem: 'Docker', name: a.name.toLowerCase(), version: a.version, origin: a.location, project, kind: 'image' };
    }
    return {
      ecosystem: 'Host',
      name: normalizeProduct(a.name),
      rawName: a.name,
      version: a.version,
      origin: a.location,
      project,
      kind: 'runtime',
      distroPackaged: Boolean(a.distro && a.distro !== 'none'),
    };
  });
}
