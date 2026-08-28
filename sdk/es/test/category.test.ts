import { test } from "node:test";
import assert from "node:assert/strict";

import { CATEGORIES, isValidCategory } from "../src/stepauth/index.js";

test("isValidCategory accepts every registered category", () => {
  for (const c of CATEGORIES) assert.equal(isValidCategory(c), true);
});

test("registry has exactly the 17 v1 categories", () => {
  assert.equal(CATEGORIES.length, 17);
});

test("isValidCategory rejects a category outside the registry", () => {
  assert.equal(isValidCategory("data.frobnicate"), false);
});
