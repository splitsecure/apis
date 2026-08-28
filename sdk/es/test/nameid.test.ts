import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseNameID,
  isValidNameID,
  isIndividual,
  email,
  persistent,
  groupId,
  policyId,
} from "../src/stepauth/index.js";

test("parseNameID splits on the first colon only", () => {
  const n = parseNameID("policy:us-east:prod");
  assert.deepEqual(n, { type: "policy", value: "us-east:prod" });
});

test("parseNameID rejects a string with no colon", () => {
  assert.throws(() => parseNameID("noColonHere"));
});

test("parseNameID rejects an unregistered type", () => {
  assert.throws(() => parseNameID("robot:r2d2"));
});

test("parseNameID rejects an empty value", () => {
  assert.throws(() => parseNameID("email:"));
});

test("isValidNameID accepts every registered type", () => {
  assert.equal(isValidNameID(email("a@b.com")), true);
  assert.equal(isValidNameID(persistent("p1")), true);
  assert.equal(isValidNameID(groupId("g1")), true);
  assert.equal(isValidNameID(policyId("pol1")), true);
});

test("isValidNameID rejects a malformed NameID", () => {
  assert.equal(isValidNameID("garbage"), false);
});

test("isIndividual accepts email and persistent", () => {
  assert.equal(isIndividual(parseNameID(email("a@b.com"))), true);
  assert.equal(isIndividual(parseNameID(persistent("p1"))), true);
});

test("isIndividual rejects group and policy", () => {
  assert.equal(isIndividual(parseNameID(groupId("g1"))), false);
  assert.equal(isIndividual(parseNameID(policyId("pol1"))), false);
});
