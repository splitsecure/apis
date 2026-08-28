import { decodeEnvelopePayload } from "./envelope.js";
import { EnvelopeFormatError } from "./crypto.js";
import type { ExecutionResult, Decision } from "./wire.js";
import { verifyDecision, type Config, type PendingState } from "./client.js";

export type { PendingState } from "./client.js";

/** Resolves a requestId to its stored PendingState, or a nullish value if
 * unknown. Return the stored state for any requestId this SP issued, with
 * `result` set once the decision has been executed — never return null for an
 * already-decided id: a null reads as a rejection, and the hub retries a
 * rejection for 24h. The SDK persists nothing; this is the caller's store
 * lookup. */
export type PendingLookup = (
  requestId: string,
) => PendingState | null | undefined | Promise<PendingState | null | undefined>;

/** Invoked with a fully verified decision; returns the ack body to send back
 * to the hub. */
export type DecisionHandler = (decision: Decision) => ExecutionResult | Promise<ExecutionResult>;

/** What createCallbackHandler's handler returns: an HTTP status plus the body
 * to write, so it drops into any server's response object. */
export interface CallbackResponse {
  status: number;
  body: ExecutionResult;
}

// One status for every rejection reason: malformed body, unknown requestId,
// each of verifyDecision's four checks, and a handler throw all come back
// identical. Varying the status by cause would itself be information a
// forged caller could use to find which check to attack next.
const REJECTED_STATUS = 401;

const MAX_CALLBACK_BODY_BYTES = 1 << 20;

function reject(): CallbackResponse {
  return { status: REJECTED_STATUS, body: { requestId: "", status: "error" } };
}

/**
 * Create a framework-agnostic handler for the hub's decision-delivery
 * webhook. The hub POSTs a signed decision to the SP's callbackUrl — there is
 * no polling, and THIS ENDPOINT CARRIES NO TRANSPORT AUTH of its own: the
 * envelope signature verified below is the entire security boundary, so
 * nothing here should special-case an unauthenticated-looking request as
 * lower-risk.
 *
 * Takes the raw body as received (a string, or the bytes before decoding) and
 * returns a status plus the ExecutionResult body; the caller writes both to
 * its actual response.
 */
export function createCallbackHandler(
  cfg: Config,
  lookup: PendingLookup,
  handler: DecisionHandler,
): (body: string | Uint8Array) => Promise<CallbackResponse> {
  return async (body) => {
    const byteLength = typeof body === "string" ? Buffer.byteLength(body) : body.length;
    if (byteLength > MAX_CALLBACK_BODY_BYTES) return reject();

    const raw = typeof body === "string" ? body : Buffer.from(body).toString();

    let requestId: string;
    try {
      const probe = JSON.parse(Buffer.from(decodeEnvelopePayload(raw)).toString()) as {
        requestId?: unknown;
      };
      if (typeof probe.requestId !== "string" || probe.requestId === "") {
        throw new EnvelopeFormatError();
      }
      requestId = probe.requestId;
    } catch {
      return reject();
    }

    // An unknown requestId is rejected BEFORE any verification is attempted:
    // there is nothing to verify a decision against, and verifying first would
    // do cryptographic work on behalf of a caller this SP never solicited.
    let pending: PendingState | null | undefined;
    try {
      pending = await lookup(requestId);
    } catch {
      return reject();
    }
    if (!pending) return reject();

    let decision: Decision;
    try {
      decision = verifyDecision(cfg, raw, pending);
    } catch {
      return reject();
    }

    // Delivery is at-least-once and the hub retries every non-2xx for 24h, so
    // a redelivery of an already-executed decision must replay the recorded
    // result rather than run the handler again.
    if (pending.result) return { status: 200, body: pending.result };

    let result: ExecutionResult;
    try {
      result = await handler(decision);
    } catch (err) {
      // Reaching here means all four verification checks passed, so this is
      // not a forged caller to stonewall: it's the protocol's own "verified,
      // but execution failed" case, and a 401 here would make the hub retry a
      // handler that may have already half-performed the action.
      return {
        status: 200,
        body: {
          requestId: decision.requestId,
          status: "error",
          error: err instanceof Error ? err.message : String(err),
        },
      };
    }

    return { status: 200, body: result };
  };
}
