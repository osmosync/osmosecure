#!/usr/bin/env node
// Validate an inventory JSON file. Usage: node validate-inventory.mjs <inventory.json>
// Exit 0 valid, 1 invalid, 2 usage or read error. Dependency-free.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateSchema } from './lib/mini-schema.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(here, '..', 'inventory-schema.json'), 'utf8'));

export function validateInventory(inv) {
  const errors = validateSchema(inv, schema);
  if (errors.length) return errors;
  const seen = new Set();
  for (const a of inv.assets) {
    if (seen.has(a.id)) errors.push(`duplicate asset id "${a.id}"`);
    seen.add(a.id);
    if (['host_runtime', 'os_package'].includes(a.kind) && !a.distro) {
      errors.push(`asset "${a.id}": ${a.kind} needs "distro" so backport rules can be applied`);
    }
    if (a.kind === 'lockfile_package' && !a.ecosystem) errors.push(`asset "${a.id}": lockfile_package needs "ecosystem"`);
    if (a.kind === 'container_image' && !a.digest) errors.push(`asset "${a.id}": container_image needs a pinned "digest"`);
    if (/^(latest|\*|x)$/i.test(a.version)) errors.push(`asset "${a.id}": version "${a.version}" is not a concrete version`);
  }
  const hostNames = new Set(inv.assets.filter((a) => a.kind === 'host_runtime').map((a) => a.name.toLowerCase()));
  inv.__missing_runtimes = ['php', 'openssl', 'nginx', 'node', 'postgres'].filter((n) => !hostNames.has(n));
  return errors;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const file = process.argv[2];
  if (!file) { console.error('usage: validate-inventory.mjs <inventory.json>'); process.exit(2); }
  let inv;
  try { inv = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { console.error(`cannot read ${file}: ${e.message}`); process.exit(2); }
  const errors = validateInventory(inv);
  if (errors.length) { errors.forEach((e) => console.error(`ERROR ${e}`)); process.exit(1); }
  if (inv.__missing_runtimes.length) console.log(`WARN no host_runtime entry for: ${inv.__missing_runtimes.join(', ')} (fine if not installed)`);
  console.log(`OK ${inv.assets.length} assets`);
}
