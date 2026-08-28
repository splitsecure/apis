import { test } from "node:test";
import assert from "node:assert/strict";

import {
  validateRequest,
  ProtocolError,
  entry,
  type AuthorizationRequest,
} from "../src/stepauth/index.js";

// Timestamps are relative to now: validation checks skew against the local
// clock, so a fixed date would start rejecting five minutes after it was written.
function baseRequest(): AuthorizationRequest {
  const now = new Date();
  return {
    requestId: "req_1",
    senderId: "sp.example.com",
    recipientId: "hub.example.com",
    timestamp: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
    principal: { subject: "email:a@b.com" },
    action: { type: "acme.widget.delete", category: "data.delete", summary: "Delete widget" },
  };
}

function codeOf(fn: () => void): string {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof ProtocolError);
    return err.code;
  }
  throw new Error("expected validateRequest to throw");
}

test("validateRequest accepts a well-formed request", () => {
  assert.doesNotThrow(() => validateRequest(baseRequest()));
});

test("validateRequest rejects a missing required field", () => {
  const req = baseRequest();
  req.requestId = "";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest accepts requestId at the 256-byte bound", () => {
  const req = baseRequest();
  req.requestId = "r".repeat(256);
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects requestId over the 256-byte bound", () => {
  const req = baseRequest();
  req.requestId = "r".repeat(257);
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest rejects a requestId containing '#'", () => {
  const req = baseRequest();
  req.requestId = "req#1";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest rejects a senderId with a non-printable byte", () => {
  const req = baseRequest();
  req.senderId = "sp\t.example.com";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest accepts action.name at the 120-codepoint bound", () => {
  const req = baseRequest();
  req.action.name = "a".repeat(120);
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects action.name over 120 codepoints", () => {
  const req = baseRequest();
  req.action.name = "a".repeat(121);
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

// The divergence this layer is most likely to introduce: JS string length
// counts UTF-16 code units, so an emoji (astral, 2 code units) would be
// double-counted against a rune-based limit unless action.name is measured by
// codepoint, matching Go's utf8.RuneCountInString.
test("validateRequest counts action.name by codepoint, not UTF-16 code unit", () => {
  const req = baseRequest();
  // 119 ASCII chars + one astral emoji = 120 codepoints, but 121 UTF-16 units.
  req.action.name = "a".repeat(119) + "\u{1F600}";
  assert.equal(req.action.name.length, 121);
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects action.name over 120 codepoints even with astral characters", () => {
  const req = baseRequest();
  req.action.name = "a".repeat(120) + "\u{1F600}";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest rejects an unknown action.category", () => {
  const req = baseRequest();
  // @ts-expect-error deliberately outside the closed registry
  req.action.category = "data.frobnicate";
  assert.equal(codeOf(() => validateRequest(req)), "unknown_category");
});

test("validateRequest accepts every registered category", () => {
  const req = baseRequest();
  req.action.category = "financial.approve";
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects a principal.subject that is not an individual NameID", () => {
  const req = baseRequest();
  req.principal.subject = "group:eng";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest accepts a persistent principal.subject", () => {
  const req = baseRequest();
  req.principal.subject = "persistent:p_123";
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects a malformed action.approver", () => {
  const req = baseRequest();
  req.action.approver = "not-a-nameid";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest accepts a well-formed action.approver", () => {
  const req = baseRequest();
  req.action.approver = "group:eng";
  assert.doesNotThrow(() => validateRequest(req));
});

// The hub falls back to the app's registered callback when callbackUrl is
// omitted; an empty string must hit that same fallback, not invalid_callback_url.
test("validateRequest accepts an empty callbackUrl", () => {
  const req = baseRequest();
  req.callbackUrl = "";
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest accepts an empty action.approver", () => {
  const req = baseRequest();
  req.action.approver = "";
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects an operator chain deeper than 5", () => {
  const req = baseRequest();
  let op: AuthorizationRequest["principal"]["operator"] = { subject: "email:l6@b.com" };
  for (let i = 0; i < 5; i++) op = { subject: `email:l${i}@b.com`, operator: op };
  req.principal.operator = op;
  assert.equal(codeOf(() => validateRequest(req)), "operator_depth_exceeded");
});

test("validateRequest accepts an operator chain exactly 5 deep", () => {
  const req = baseRequest();
  let op: AuthorizationRequest["principal"]["operator"] = { subject: "email:l5@b.com" };
  for (let i = 0; i < 4; i++) op = { subject: `email:l${i}@b.com`, operator: op };
  req.principal.operator = op;
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest accepts an https callbackUrl", () => {
  const req = baseRequest();
  req.callbackUrl = "https://sp.example.com/hooks/stepauth";
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest accepts an http callbackUrl to localhost", () => {
  const req = baseRequest();
  req.callbackUrl = "http://localhost:4000/hooks/stepauth";
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects a non-loopback http callbackUrl", () => {
  const req = baseRequest();
  req.callbackUrl = "http://sp.example.com/hooks/stepauth";
  assert.equal(codeOf(() => validateRequest(req)), "invalid_callback_url");
});

test("validateRequest rejects an unparseable callbackUrl", () => {
  const req = baseRequest();
  req.callbackUrl = "not a url";
  assert.equal(codeOf(() => validateRequest(req)), "invalid_callback_url");
});

test("validateRequest rejects a duplicate labeled-entry key in action.details", () => {
  const req = baseRequest();
  req.action.details = [entry("amount", "Amount", "1"), entry("amount", "Amount", "2")];
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest accepts unique labeled-entry keys in principal.attributes", () => {
  const req = baseRequest();
  req.principal.attributes = [entry("department", "Department", "eng")];
  assert.doesNotThrow(() => validateRequest(req));
});

test("validateRequest rejects a non-RFC3339 timestamp", () => {
  const req = baseRequest();
  req.timestamp = "not-a-time";
  assert.equal(codeOf(() => validateRequest(req)), "timestamp_out_of_range");
});

test("validateRequest rejects a non-RFC3339 expiresAt", () => {
  const req = baseRequest();
  req.expiresAt = "not-a-time";
  assert.equal(codeOf(() => validateRequest(req)), "malformed_request");
});

test("validateRequest accepts RFC3339 timestamps with an explicit offset", () => {
  const req = baseRequest();
  // The same instant as now, written with a -04:00 offset instead of Z, so this
  // exercises offset parsing without tripping the skew check.
  const now = new Date();
  const local = new Date(now.getTime() - 4 * 60 * 60_000).toISOString().replace(/Z$/, "-04:00");
  req.timestamp = local;
  req.expiresAt = new Date(now.getTime() + 30 * 60_000).toISOString();
  assert.doesNotThrow(() => validateRequest(req));
});
