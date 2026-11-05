import { normalizeProduct } from '../inventory/host.js';
import type { Component, FeedItem } from '../types.js';

/** Spelling variants seen in disclosures mapped to the product names used by the inventory. */
const ALIASES = new Map<string, string>(Object.entries({
  'node.js': 'node',
  nodejs: 'node',
  postgresql: 'postgres',
  libssl: 'openssl',
  'docker-ce': 'docker',
  'redis-server': 'redis',
}));

export function imageBasename(repository: string): string {
  const parts = repository.split('/');
  return parts[parts.length - 1];
}

/** Product terms that free-text disclosures are screened against: host runtimes and image names. */
export function buildProductTerms(components: Component[]): Set<string> {
  const terms = new Set<string>();
  for (const c of components) {
    if (c.kind === 'runtime') terms.add(c.name);
    else if (c.kind === 'image') terms.add(normalizeProduct(imageBasename(c.name)));
  }
  return terms;
}

export function buildPackageNames(components: Component[]): Set<string> {
  return new Set(components.filter((c) => c.kind === 'package').map((c) => c.name));
}

function tokens(text: string): string[] {
  const raw = text.toLowerCase().match(/[a-z0-9][a-z0-9._@/-]*[a-z0-9]|[a-z0-9]/g) ?? [];
  // A bare "node" in prose (node, DOM node, tree node) is not the runtime; require node.js / nodejs.
  return raw.filter((t) => t !== 'node').map((t) => ALIASES.get(t) ?? t);
}

/**
 * Cheap deterministic screen run before any LLM call. A free-text item passes when it names a
 * product we run (host runtime or container image), or when a structured hint (CPE product)
 * equals one of our package names. When structured hints exist they decide on their own, so
 * a CVE whose CPE data names other products is not sent to the model on a stray prose match.
 */
export function prefilter(item: FeedItem, productTerms: Set<string>, packageNames: Set<string>): boolean {
  if (item.productHints.length > 0) {
    for (const hint of item.productHints) {
      const h = (ALIASES.get(hint.toLowerCase()) ?? hint.toLowerCase()).replace(/_/g, '-');
      if (productTerms.has(normalizeProduct(h)) || packageNames.has(h)) return true;
    }
    return false;
  }
  for (const t of tokens(`${item.title} ${item.text}`)) {
    if (productTerms.has(normalizeProduct(t))) return true;
  }
  return false;
}
