import { test } from "node:test";
import assert from "node:assert/strict";

import { ProtocolError, isRetryable } from "../src/stepauth/index.js";

test("ProtocolError maps a known code to its documented HTTP status", () => {
  assert.equal(new ProtocolError("invalid_signature", "bad sig").httpStatus, 401);
  assert.equal(new ProtocolError("duplicate_request", "dup").httpStatus, 409);
  assert.equal(new ProtocolError("request_not_found", "gone").httpStatus, 404);
  assert.equal(new ProtocolError("wrong_recipient", "not you").httpStatus, 403);
});

test("ProtocolError falls back to 400 for an unrecognized code", () => {
  const err = new ProtocolError("some_future_code", "unknown");
  assert.equal(err.httpStatus, 400);
  assert.equal(err.code, "some_future_code");
});

test("isRetryable is false for every known code", () => {
  assert.equal(isRetryable(new ProtocolError("duplicate_request", "dup")), false);
  assert.equal(isRetryable(new ProtocolError("timestamp_out_of_range", "skew")), false);
});

test("isRetryable fails closed for an unrecognized code", () => {
  assert.equal(isRetryable(new ProtocolError("some_future_code", "unknown")), false);
});

test("isRetryable is false for a non-ProtocolError", () => {
  assert.equal(isRetryable(new Error("network blip")), false);
});

// Without this the classifier can be implemented as a constant false and every
// other case above still passes.
test("isRetryable is true for a hub 5xx", () => {
  assert.equal(isRetryable(new ProtocolError("internal_error", "hub failed", 500)), true);
  assert.equal(isRetryable(new ProtocolError("internal_error", "unavailable", 503)), true);
});
