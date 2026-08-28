import { randomBytes, createHash } from "node:crypto";

import { signEnvelope, verifyEnvelope } from "./envelope.js";
import { validateKeyset, type Keyset, type SigningKeyset } from "./crypto.js";
import { validateRequest } from "./validate.js";
import { ProtocolError, TransportError, isRetryable } from "./errors.js";
import type {
  AuthorizationRequest,
  Decision,
  ExecutionResult,
  PendingResponse,
  Principal,
  Action,
} from "./wire.js";

/** This SP's metadata: its entity id, and the callbackUrl a request falls
 * back to when it doesn't set its own. */
export interface SPMetadata {
  entity: string;
  callbackUrl?: string;
}

/** A hub's metadata document, as published at GET {host}/v1/metadata. */
export interface HubMetadata {
  entity: string;
  keysets: Keyset[];
  /** The transport origin to POST to. NEVER derive this from entity — the hub
   * serves each org under a path prefix, so it may be path-prefixed behind a
   * proxy. */
  host: string;
}

/** One hub this SP can submit to, named by a local tag. Exactly one entry in
 * Config.hubs must be default. */
export interface HubEntry {
  tag: string;
  metadata: HubMetadata;
  default?: boolean;
}

/** SDK-wide configuration: this SP's identity, its signing key, and the hubs
 * it talks to. */
export interface Config {
  signingKeyset: SigningKeyset;
  sp: SPMetadata;
  hubs: HubEntry[];
  /** Injectable fetch, for tests. Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
}

/** What the SP MUST persist for a submitted request until a terminal outcome:
 * the request payload bytes (what the decision's requestDigest is computed
 * over) and which hub it went to — its local tag (to resolve keysets on the
 * way back) and its entity as recorded AT SEND TIME (so a later re-tag of
 * Config cannot change what a decision must match). JSON-serializable; the SDK
 * persists nothing itself. */
export interface PendingState {
  requestId: string;
  hub: string;
  hubEntity: string;
  /** The exact request payload bytes that were signed, base64. */
  payload: string;
  /** The ExecutionResult already recorded for this request, if the SP has
   * executed it. Delivery is at-least-once, so a redelivery must replay
   * this rather than run the handler again. */
  result?: ExecutionResult;
}

/** A caller-supplied request, before the wire fields this SDK fills are added. */
export interface SendRequestInput {
  hub?: string;
  requestId?: string;
  timestamp?: Date;
  expiresAt?: Date;
  callbackUrl?: string;
  principal: Principal;
  action: Action;
  policyVersion?: string;
}

/** The 202 body, plus the retransmit case: a duplicate_request the hub
 * returned to OUR OWN retry of the same bytes. alreadySubmitted is true only
 * there; the hub never re-reports createdAt for a request it already created. */
export interface SendResult extends Omit<PendingResponse, "createdAt"> {
  createdAt?: string;
  alreadySubmitted?: boolean;
}

const DEFAULT_EXPIRES_IN_MS = 30 * 60 * 1000;
const MAX_ATTEMPTS = 3;
// Backoff between attempts; three attempts, two waits, comfortably under 30s.
const BACKOFF_MS = [1000, 4000];

const SUBMIT_PATH = "/v1/authorization-requests";


/** Rejected because a verified decision's senderId doesn't match the hub the
 * request was sent to (recorded in PendingState at send time). */
export class SenderMismatchError extends Error {
  constructor() {
    super("stepauth: decision senderId does not match the hub this request was sent to");
    this.name = "SenderMismatchError";
  }
}

/** Rejected because a verified decision's recipientId isn't this SP. */
export class RecipientMismatchError extends Error {
  constructor() {
    super("stepauth: decision recipientId does not match this SP");
    this.name = "RecipientMismatchError";
  }
}

/** Rejected because a verified decision's requestDigest doesn't match the
 * stored request payload. */
export class DigestMismatchError extends Error {
  constructor() {
    super("stepauth: decision requestDigest does not match the stored request");
    this.name = "DigestMismatchError";
  }
}


/** Validate Config: signing keyset present, SP entity set, at least one hub,
 * exactly one default, every hub with a host, entity, and at least one keyset. */
export function validateConfig(cfg: Config): void {
  if (!cfg.signingKeyset || cfg.signingKeyset.keys.length === 0) {
    throw new Error("stepauth: Config.signingKeyset is required");
  }
  if (!cfg.sp?.entity) throw new Error("stepauth: Config.sp.entity is required");
  if (!cfg.hubs || cfg.hubs.length === 0) throw new Error("stepauth: at least one hub is required");

  let defaults = 0;
  for (const h of cfg.hubs) {
    if (!h.metadata?.host) throw new Error(`stepauth: hub "${h.tag}" is missing metadata.host`);
    if (!h.metadata?.entity) throw new Error(`stepauth: hub "${h.tag}" is missing metadata.entity`);
    if (!h.metadata?.keysets?.length) throw new Error(`stepauth: hub "${h.tag}" has no keysets`);
    h.metadata.keysets.forEach(validateKeyset);
    if (h.default) defaults++;
  }
  if (defaults !== 1) {
    throw new Error(`stepauth: exactly one hub must be default, found ${defaults}`);
  }
}

function hubByTag(cfg: Config, tag: string | undefined): HubEntry {
  const hub = tag ? cfg.hubs.find((h) => h.tag === tag) : cfg.hubs.find((h) => h.default);
  if (!hub) throw new Error(`stepauth: no configured hub for tag "${tag}"`);
  return hub;
}

/** The hub's base URL: origin plus any path prefix it is mounted under. */
function hubBase(hub: HubEntry): string {
  return hub.metadata.host.replace(/\/+$/, "");
}

/** RFC3339 without sub-second precision, matching the hub's time.RFC3339. */
function rfc3339(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function buildRequest(cfg: Config, hub: HubEntry, req: SendRequestInput): AuthorizationRequest {
  const now = req.timestamp ?? new Date();
  const expiresAt =
    req.expiresAt ?? new Date(now.getTime() + DEFAULT_EXPIRES_IN_MS);
  return {
    requestId: req.requestId || "req_" + randomBytes(16).toString("hex"),
    senderId: cfg.sp.entity,
    recipientId: hub.metadata.entity,
    timestamp: rfc3339(now),
    expiresAt: rfc3339(expiresAt),
    callbackUrl: req.callbackUrl ?? cfg.sp.callbackUrl,
    principal: req.principal,
    action: req.action,
    policyVersion: req.policyVersion,
  };
}

function parseProtocolError(status: number, body: string): ProtocolError {
  let code = "";
  let message = "";
  try {
    const parsed = JSON.parse(body) as { error?: string; message?: string };
    code = parsed.error ?? "";
    message = parsed.message ?? "";
  } catch {
    // non-JSON body
  }
  return new ProtocolError(code || "internal_error", message, status);
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      // The caller's abort reason is passed through verbatim rather than
      // wrapped, so they can tell their own abort from a transport failure.
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
      reject(signal.reason);
    }, { once: true });
  });
}

const MAX_RESPONSE_BYTES = 1 << 20;
const REQUEST_TIMEOUT_MS = 30_000;

/** Combine the caller's abort signal with a fixed request timeout. */
function withTimeout(signal: AbortSignal | undefined): AbortSignal {
  return AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)].filter(
    (s): s is AbortSignal => s !== undefined,
  ));
}

async function readBoundedBody(resp: Response): Promise<string> {
  const reader = resp.body?.getReader();
  if (!reader) return resp.text();

  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new ProtocolError("internal_error", "response body exceeds the size limit", resp.status);
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

/**
 * Build, sign, and submit an authorization request to the hub selected by
 * req.hub (or the default hub). Signs the envelope ONCE and retries with
 * those exact bytes: re-signing would change the digest and void the
 * PendingState verifyDecision needs later. Returns the hub's response plus
 * the PendingState the caller MUST persist.
 */
export async function sendRequest(
  cfg: Config,
  req: SendRequestInput,
  signal?: AbortSignal,
): Promise<{ result: SendResult; state: PendingState }> {
  validateConfig(cfg);
  const hub = hubByTag(cfg, req.hub);

  const wire = buildRequest(cfg, hub, req);
  validateRequest(wire);
  const payload = new TextEncoder().encode(JSON.stringify(wire));
  const envelopeJSON = signEnvelope(cfg.signingKeyset, payload); // frozen: never re-signed below

  const state: PendingState = {
    requestId: wire.requestId,
    hub: hub.tag,
    hubEntity: hub.metadata.entity,
    payload: Buffer.from(payload).toString("base64"),
  };

  const fetchFn = cfg.fetch ?? fetch;
  const url = hubBase(hub) + SUBMIT_PATH;

  let lastErr: unknown;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    if (signal?.aborted) throw signal.reason;
    let status: number;
    let body: string;
    try {
      const resp = await fetchFn(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: envelopeJSON,
        signal: withTimeout(signal),
      });
      status = resp.status;
      body = await readBoundedBody(resp);
    } catch (cause) {
      lastErr = new TransportError(cause);
      if (attempt < MAX_ATTEMPTS && isRetryable(lastErr)) {
        await sleep(BACKOFF_MS[attempt - 1], signal);
        continue;
      }
      throw lastErr;
    }

    if (status === 202) {
      // The hub accepted the request. A malformed body must not throw away
      // the state the caller needs to verify the decision.
      try {
        return { result: JSON.parse(body) as PendingResponse, state };
      } catch {
        return { result: { requestId: wire.requestId, status: "pending" }, state };
      }
    }

    const err = parseProtocolError(status, body);

    // A 409 on attempt >= 2 proves THIS client already transmitted these exact
    // bytes on a prior attempt whose response was lost — the request landed,
    // so this is our own retry colliding with itself, not someone else's id.
    // On attempt 1 this client has sent nothing yet, so the same code means a
    // real collision: the id belongs to another request.
    if (err.code === "duplicate_request" && attempt >= 2) {
      return { result: { requestId: wire.requestId, status: "pending", alreadySubmitted: true }, state };
    }

    lastErr = err;
    if (attempt < MAX_ATTEMPTS && isRetryable(err)) {
      await sleep(BACKOFF_MS[attempt - 1], signal);
      continue;
    }
    throw err;
  }

  throw lastErr;
}

/**
 * Verify a signed decision envelope against the stored PendingState, in the
 * required order (any failure rejects, each with its own error so a caller
 * can log which failed). Passing the signature check but failing a later one
 * means a substituted hub, a decision replayed to another SP, or a decision
 * bound to a different request.
 */
export function verifyDecision(
  cfg: Config,
  envelopeJSON: string | Uint8Array,
  state: PendingState,
): Decision {
  validateConfig(cfg);
  const hub = hubByTag(cfg, state.hub);

  const raw = typeof envelopeJSON === "string" ? envelopeJSON : Buffer.from(envelopeJSON).toString();
  const payload = verifyEnvelope(raw, hub.metadata.keysets); // 1. all-of signature
  const decision = JSON.parse(Buffer.from(payload).toString()) as Decision;

  if (decision.senderId !== state.hubEntity) throw new SenderMismatchError(); // 2
  if (decision.recipientId !== cfg.sp.entity) throw new RecipientMismatchError(); // 3

  const storedPayload = requestPayloadOf(state);
  const wantDigest = createHash("sha256").update(storedPayload).digest("base64");
  if (decision.requestDigest.algorithm !== "sha256" || decision.requestDigest.value !== wantDigest) {
    throw new DigestMismatchError(); // 4
  }

  return decision;
}

/** The raw request payload bytes recorded at send time. Shared with
 * callback.ts, which verifies against the same PendingState. */
export function requestPayloadOf(state: PendingState): Uint8Array {
  return new Uint8Array(Buffer.from(state.payload, "base64"));
}

/** A page of a directory listing. */
export interface DirectoryPage<T> {
  items: T[];
  nextCursor?: string;
}

/** One entry in a users/groups/policies directory response. */
export interface DirectoryItem {
  id: string;
  label?: string;
  provenance?: string;
  namespace?: string;
  count?: number;
}

const DIRECTORY_PATHS = {
  users: "/v1/users",
  groups: "/v1/groups",
  policies: "/v1/policies",
} as const;

/** Which approver directory to query. */
export type DirectoryKind = keyof typeof DIRECTORY_PATHS;

/**
 * Query one page of a hub's approver directory (users, groups, or policies).
 * The query is a signed DirectoryQuery envelope in the POST body — requestUri
 * is set to this endpoint's own path, binding the signature to it so it can't
 * be replayed against a different resource or org.
 */
export async function queryDirectory(
  cfg: Config,
  kind: DirectoryKind,
  opts: { hub?: string; limit?: number; cursor?: string; signal?: AbortSignal } = {},
): Promise<DirectoryPage<DirectoryItem>> {
  validateConfig(cfg);
  const hub = hubByTag(cfg, opts.hub);
  const path = DIRECTORY_PATHS[kind];

  // requestUri must be the full path as sent, hub prefix included: the hub
  // compares it against its own r.URL.RequestURI(), and a path-prefixed tenant
  // rejects a bare "/v1/users" as a replay against a different resource.
  const target = hubBase(hub) + path;
  const { pathname, search } = new URL(target);

  const query = {
    senderId: cfg.sp.entity,
    recipientId: hub.metadata.entity,
    requestUri: pathname + search,
    timestamp: rfc3339(new Date()),
    ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
    ...(opts.cursor !== undefined ? { cursor: opts.cursor } : {}),
  };
  const payload = new TextEncoder().encode(JSON.stringify(query));
  const envelopeJSON = signEnvelope(cfg.signingKeyset, payload);

  const fetchFn = cfg.fetch ?? fetch;
  const resp = await fetchFn(target, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: envelopeJSON,
    signal: withTimeout(opts.signal),
  });
  const body = await readBoundedBody(resp);
  if (resp.status !== 200) throw parseProtocolError(resp.status, body);
  return JSON.parse(body) as DirectoryPage<DirectoryItem>;
}
