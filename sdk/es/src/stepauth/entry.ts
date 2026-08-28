import type { LabeledEntry } from "./wire.js";

/** Create a labeled entry with a string value. */
export function entry(key: string, label: string, value: string): LabeledEntry {
  return { key, label, value };
}

/** Create a labeled entry with nested child entries. */
export function group(key: string, label: string, ...children: LabeledEntry[]): LabeledEntry {
  return { key, label, value: children };
}

/** Convenience: return arguments as an array. */
export function entries(...items: LabeledEntry[]): LabeledEntry[] {
  return items;
}

/**
 * Validate labeled-entry keys for intra-array uniqueness, recursively into
 * nested groups. The hub matches on Label, never Key, and enforces no key
 * charset, so this doesn't either. Throws on the first violation.
 */
export function validateEntries(items: LabeledEntry[]): void {
  const seen = new Set<string>();
  for (const e of items) {
    if (seen.has(e.key)) {
      throw new Error(`stepauth: duplicate entry key "${e.key}"`);
    }
    seen.add(e.key);
    if (Array.isArray(e.value)) {
      validateEntries(e.value);
      continue;
    }
    // A leaf string or a child array. Any other shape is not an entry the hub
    // can render.
    if (typeof e.value !== "string") {
      throw new Error(`stepauth: entry "${e.key}" value must be a string or an array`);
    }
  }
}
