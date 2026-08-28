/** Registered NameID type prefixes (`type:value`). */
export const NAMEID_EMAIL = "email";
export const NAMEID_PERSISTENT = "persistent";
export const NAMEID_GROUP = "group";
export const NAMEID_POLICY = "policy";

const REGISTERED = new Set([NAMEID_EMAIL, NAMEID_PERSISTENT, NAMEID_GROUP, NAMEID_POLICY]);

/** A parsed `type:value` identifier. */
export interface NameID {
  type: string;
  value: string;
}

/**
 * Split s on the FIRST colon only. The value may itself contain colons; only
 * the type prefix must be one of the registered types, and the value must be
 * non-empty. Throws on a malformed NameID.
 */
export function parseNameID(s: string): NameID {
  const i = s.indexOf(":");
  if (i < 0) throw new Error(`stepauth: nameid "${s}": missing ':'`);
  const type = s.slice(0, i);
  const value = s.slice(i + 1);
  if (!REGISTERED.has(type)) {
    throw new Error(`stepauth: nameid "${s}": unknown type "${type}"`);
  }
  if (value === "") throw new Error(`stepauth: nameid "${s}": empty value`);
  return { type, value };
}

/** Reports whether s is a well-formed NameID. */
export function isValidNameID(s: string): boolean {
  try {
    parseNameID(s);
    return true;
  } catch {
    return false;
  }
}

/** Reports whether n is a single person — the only kind allowed as principal.subject. */
export function isIndividual(n: NameID): boolean {
  return n.type === NAMEID_EMAIL || n.type === NAMEID_PERSISTENT;
}

export const email = (addr: string): string => `${NAMEID_EMAIL}:${addr}`;
export const persistent = (id: string): string => `${NAMEID_PERSISTENT}:${id}`;
export const groupId = (id: string): string => `${NAMEID_GROUP}:${id}`;
export const policyId = (id: string): string => `${NAMEID_POLICY}:${id}`;
