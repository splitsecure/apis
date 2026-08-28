import type { Category } from "./category.js";

/** Decision.decision values (wire.lock [const]). */
export const DECISION_APPROVED = "approved";
export const DECISION_DENIED = "denied";
export type DecisionStatus = typeof DECISION_APPROVED | typeof DECISION_DENIED;

/** Digest.algorithm value (wire.lock [const]); the only one in v1. */
export const DIGEST_SHA256 = "sha256";

/** How far a request timestamp may sit from the hub's clock (wire.lock [const]). */
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

/** A display entry in principal.attributes / action.details. Value is a
 * string, or nested children for a grouping entry. */
export interface LabeledEntry {
  key: string;
  label: string;
  value: string | LabeledEntry[];
}

/** The resource an action acts upon. Not a NameID. */
export interface Target {
  id: string;
  kind: string;
}

/** The request initiator plus an optional informational operator chain. */
export interface Principal {
  subject: string;
  attributes?: LabeledEntry[];
  operator?: Principal;
}

/** The sensitive operation under review. */
export interface Action {
  type: string;
  category: Category;
  /** Short imperative title. Optional: an SP that sends none is titled by type, then summary. */
  name?: string;
  summary: string;
  details?: LabeledEntry[];
  target?: Target;
  approver?: string;
}

/** The decoded payload of a submission envelope. */
export interface AuthorizationRequest {
  requestId: string;
  /** The SP entity the hub resolves the registration and verifying keysets by. */
  senderId: string;
  /** The target hub tenant; a request not addressed to this tenant is rejected. */
  recipientId: string;
  timestamp: string;
  expiresAt: string;
  callbackUrl?: string;
  principal: Principal;
  action: Action;
  policyVersion?: string;
}

/** The request-payload hash carried in a Decision. */
export interface Digest {
  algorithm: string;
  value: string;
}

/** The decoded payload of a decision envelope. */
export interface Decision {
  requestId: string;
  /** This hub tenant's entity. */
  senderId: string;
  /** The SP's entity. */
  recipientId: string;
  decision: DecisionStatus;
  decidedAt: string;
  decidedBy: string[];
  requestDigest: Digest;
}

/** The 202 body returned by submit. */
export interface PendingResponse {
  requestId: string;
  status: "pending";
  createdAt: string;
  reviewDescription?: string;
}

/** The SP's acknowledgement of a delivered decision. */
export interface ExecutionResult {
  requestId: string;
  status: "success" | "error";
  error?: string;
}
