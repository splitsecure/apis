import { MAX_CLOCK_SKEW_MS } from "./wire.js";
import type { AuthorizationRequest, LabeledEntry, Principal } from "./wire.js";
import { isValidCategory } from "./category.js";
import { isIndividual, isValidNameID, parseNameID } from "./nameid.js";
import { validateEntries } from "./entry.js";
import { ProtocolError } from "./errors.js";

const MAX_KEY_ID_LEN = 256;
/** action.name bound, in codepoints. */
const MAX_ACTION_NAME_LEN = 120;
const MAX_OPERATOR_DEPTH = 5;

const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isRFC3339(s: string): boolean {
  return RFC3339_RE.test(s) && !Number.isNaN(Date.parse(s));
}

/** Codepoint count, matching Go's utf8.RuneCountInString: `s.length` counts
 * UTF-16 code units and over-counts anything outside the BMP (emoji, many CJK
 * extension characters), so TS and Go would disagree on identical input. */
function runeLength(s: string): number {
  return [...s].length;
}

/** ids spliced into DynamoDB sort keys: non-empty, bounded, printable ASCII,
 * no '#' (the sort-key delimiter — an embedded one could straddle another
 * id's key range). */
function isValidKeyID(id: string): boolean {
  if (id === "" || id.length > MAX_KEY_ID_LEN) return false;
  for (let i = 0; i < id.length; i++) {
    const c = id.charCodeAt(i);
    if (c === 0x23 || c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

function malformed(message: string): never {
  throw new ProtocolError("malformed_request", message);
}

function callbackAllowed(url: URL): boolean {
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
}

function validateCallbackURL(callbackUrl: string | undefined): void {
  if (!callbackUrl) return;
  let url: URL;
  try {
    url = new URL(callbackUrl);
  } catch {
    throw new ProtocolError("invalid_callback_url", "callbackUrl is not a valid URL");
  }
  if (!callbackAllowed(url)) {
    throw new ProtocolError("invalid_callback_url", "callbackUrl must be https");
  }
}

function validateOperatorDepth(principal: Principal): void {
  let depth = 0;
  for (let p = principal.operator; p; p = p.operator) {
    depth++;
    if (depth > MAX_OPERATOR_DEPTH) {
      throw new ProtocolError("operator_depth_exceeded", "operator chain deeper than 5");
    }
  }
}

function validateLabeledEntries(items: LabeledEntry[] | undefined): void {
  if (!items) return;
  try {
    validateEntries(items);
  } catch (err) {
    malformed(err instanceof Error ? err.message : "invalid labeled entry");
  }
}

/**
 * Pre-send validation mirroring the hub's own checks. Throws a ProtocolError
 * with the code the hub would return for the same defect.
 */
export function validateRequest(req: AuthorizationRequest): void {
  if (req.requestId === "") malformed("missing requestId");
  if (req.senderId === "") malformed("missing senderId");
  if (req.recipientId === "") malformed("missing recipientId");
  if (req.timestamp === "") malformed("missing timestamp");
  if (req.expiresAt === "") malformed("missing expiresAt");
  if (req.action.type === "") malformed("missing action.type");
  if ((req.action.category as string) === "") malformed("missing action.category");
  if (req.action.summary === "") malformed("missing action.summary");
  if (req.principal.subject === "") malformed("missing principal.subject");

  if (!isValidKeyID(req.requestId)) malformed("requestId has invalid characters or is too long");
  if (!isValidKeyID(req.senderId)) malformed("senderId has invalid characters or is too long");

  if (runeLength(req.action.name ?? "") > MAX_ACTION_NAME_LEN) {
    malformed(`action.name is longer than ${MAX_ACTION_NAME_LEN} characters`);
  }
  if (!isValidCategory(req.action.category)) {
    throw new ProtocolError("unknown_category", `unknown action.category: ${String(req.action.category)}`);
  }

  if (!isRFC3339(req.timestamp)) {
    throw new ProtocolError("timestamp_out_of_range", "timestamp is not RFC3339");
  }
  // Checked against the local clock. The hub's clock is authoritative; this
  // only catches a stale or wrongly built timestamp before it costs a round
  // trip.
  if (Math.abs(Date.now() - Date.parse(req.timestamp)) > MAX_CLOCK_SKEW_MS) {
    throw new ProtocolError("timestamp_out_of_range", "timestamp skew exceeds 5m");
  }
  if (!isRFC3339(req.expiresAt)) malformed("expiresAt is not RFC3339");

  validateOperatorDepth(req.principal);

  const subject = isValidNameID(req.principal.subject) ? parseNameID(req.principal.subject) : null;
  if (!subject || !isIndividual(subject)) {
    malformed("principal.subject must be an individual NameID");
  }
  if (req.action.approver && !isValidNameID(req.action.approver)) {
    malformed("action.approver must be a valid NameID");
  }

  validateCallbackURL(req.callbackUrl);

  validateLabeledEntries(req.principal.attributes);
  validateLabeledEntries(req.action.details);
}
