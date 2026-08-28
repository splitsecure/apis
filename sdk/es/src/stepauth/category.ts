/** The closed v1 action-category registry. */
export const CATEGORIES = [
  "data.read",
  "data.export",
  "data.modify",
  "data.delete",
  "identity.create",
  "identity.modify",
  "identity.escalate",
  "identity.disable",
  "infra.modify",
  "infra.destroy",
  "financial.transfer",
  "financial.approve",
  "code.deploy",
  "code.release",
  "communication.send",
  "access.grant",
  "access.revoke",
] as const;

export type Category = (typeof CATEGORIES)[number];

const VALID = new Set<string>(CATEGORIES);

/** Reports whether c is in the closed v1 registry. */
export function isValidCategory(c: string): c is Category {
  return VALID.has(c);
}
