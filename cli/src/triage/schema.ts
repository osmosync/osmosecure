import { z } from 'zod';

const versionString = z
  .string()
  .max(40)
  .regex(/^[0-9][0-9A-Za-z.+~:_-]*$/, 'not a version');

/** Model free text is untrusted: strip control characters so it cannot forge log lines or message structure. */
const plainText = (max: number) =>
  z
    .string()
    .max(max)
    .transform((t) => t.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').replace(/\s+/g, ' ').trim());

/** Product names are only ever compared with inventory names. Anything outside a plain-name alphabet is blanked, never passed on. */
const productName = z
  .string()
  .min(1)
  .max(80)
  .transform((t) => t.replace(/[^A-Za-z0-9 ._+@/:-]+/g, ' ').replace(/\s+/g, ' ').trim())
  .refine((t) => t.length > 0 && /^[A-Za-z0-9@]/.test(t), 'not a product name');

const range = z.object({
  introduced: versionString.nullable().default(null),
  fixed: versionString.nullable().default(null),
  lastAffected: versionString.nullable().default(null),
});

export const productSchema = z.object({
  /** Lowercase product name such as php, openssl, nginx, node, postgres, lodash. */
  name: productName,
  ecosystem: z.enum(['npm', 'Packagist', 'RubyGems', 'PyPI', 'Docker', 'Host', 'unknown']).default('unknown'),
  affectedRanges: z.array(range).max(10).default([]),
  /** One entry per supported release branch, for example 8.1.30, 8.2.24, 8.3.12. */
  fixedVersions: z.array(versionString).max(12).default([]),
});

export const triageSchema = z.object({
  relevant: z.boolean(),
  cves: z.array(z.string().regex(/^CVE-\d{4}-\d{4,7}$/i)).max(20).default([]),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'unknown']).default('unknown'),
  exploitedInWild: z.enum(['yes', 'no', 'unknown']).default('unknown'),
  products: z.array(productSchema).max(8).default([]),
  summary: plainText(400).default(''),
});

export type TriageProduct = z.infer<typeof productSchema>;
export type TriageResult = z.infer<typeof triageSchema>;

/** Pulls the first JSON object out of a model reply and validates it. Throws on anything else. */
export function parseTriageReply(reply: string): TriageResult {
  const start = reply.indexOf('{');
  const end = reply.lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('triage reply contained no JSON object');
  return triageSchema.parse(JSON.parse(reply.slice(start, end + 1)));
}
