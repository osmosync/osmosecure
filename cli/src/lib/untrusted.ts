/**
 * Shared normalisation for text that came from outside (feeds, repository files, model output).
 *
 * Invisible and look-alike characters are a known way to hide instructions from a human reviewer or to dodge a
 * delimiter check, so they are removed or folded before any other rule runs. This is one layer, not a defense on its
 * own: see docs/threat-model.md.
 */

/** Zero-width, bidirectional control, Unicode "tag" (ASCII smuggling), variation selector and BOM characters. */
const INVISIBLE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]|[\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/g;

/** NFKC folds full-width and other compatibility forms (for example a full-width "<") to their plain equivalents. */
export function normalizeUntrusted(text: string): string {
  return text.normalize('NFKC').replace(INVISIBLE, '').replace(CONTROL, ' ');
}

/** True when the text carries invisible or bidirectional characters (normalizeUntrusted would remove them). */
export function hasHiddenChars(text: string): boolean {
  INVISIBLE.lastIndex = 0;
  const hidden = INVISIBLE.test(text);
  INVISIBLE.lastIndex = 0;
  return hidden;
}
