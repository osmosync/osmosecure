export interface ImageRef {
  repository: string;
  tag: string;
  raw: string;
}

/** Extracts `image:` values from docker-compose YAML without a YAML dependency. */
export function parseComposeImages(text: string): ImageRef[] {
  const out: ImageRef[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*image:\s*["']?([^"'\s#]+)["']?/.exec(line);
    if (!m) continue;
    const raw = m[1];
    // Variable-driven refs like ${IMAGE} or ${TAG:-1.2} have no static version; keep the default when given.
    const withDefault = raw.replace(/\$\{[A-Za-z0-9_]+:?-([^}]*)\}/g, '$1');
    if (withDefault.includes('${')) continue;
    const ref = withDefault.replace(/@sha256:[a-f0-9]+$/, '');
    const lastSlash = ref.lastIndexOf('/');
    const colon = ref.indexOf(':', lastSlash + 1);
    const repository = (colon >= 0 ? ref.slice(0, colon) : ref).toLowerCase();
    const tag = colon >= 0 ? ref.slice(colon + 1) : 'latest';
    const key = `${repository}:${tag}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ repository, tag, raw });
  }
  return out;
}
