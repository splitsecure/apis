import { test } from "node:test";
import assert from "node:assert/strict";

import { entry, group, entries, validateEntries } from "../src/stepauth/index.js";

test("validateEntries accepts well-formed unique keys", () => {
  assert.doesNotThrow(() =>
    validateEntries(entries(entry("amount", "Amount", "100"), entry("currency", "Currency", "usd"))),
  );
});

test("validateEntries accepts a camelCase key", () => {
  assert.doesNotThrow(() => validateEntries(entries(entry("userId", "User ID", "u_1"))));
});

test("validateEntries accepts a key starting with a letter followed by digits/underscore", () => {
  assert.doesNotThrow(() => validateEntries(entries(entry("field_2", "Field 2", "x"))));
});

test("validateEntries rejects duplicate keys at the same level", () => {
  assert.throws(() =>
    validateEntries(entries(entry("amount", "Amount", "100"), entry("amount", "Amount again", "200"))),
  );
});

test("validateEntries accepts the same key reused across sibling groups", () => {
  assert.doesNotThrow(() =>
    validateEntries(
      entries(
        group("a", "A", entry("amount", "Amount", "1")),
        group("b", "B", entry("amount", "Amount", "2")),
      ),
    ),
  );
});

test("validateEntries rejects a duplicate key nested inside one group", () => {
  assert.throws(() =>
    validateEntries(
      entries(group("a", "A", entry("amount", "Amount", "1"), entry("amount", "Amount", "2"))),
    ),
  );
});
