import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ALG_ED25519,
  ALG_ML_DSA_65,
  KEYSET_ALGS,
  InvalidSignatureError,
  EnvelopeFormatError,
  generateKeyset,
  keyFromSeed,
  publicKeyset,
  signingKeysetToJSON,
  signingKeysetFromJSON,
  signEnvelope,
  verifyEnvelope,
  decodeEnvelopePayload,
  type Envelope,
  type SigningKeyset,
} from "../src/stepauth/index.js";
import { signComponent, verifyComponent } from "../src/stepauth/crypto.js";

const b64 = (s: string) => Buffer.from(s).toString("base64");

function testKeyset(): SigningKeyset {
  return generateKeyset("ks_test");
}

function reEncode(envelopeJSON: string, fn: (env: Envelope) => void): string {
  const env = JSON.parse(envelopeJSON) as Envelope;
  fn(env);
  return JSON.stringify(env);
}

test("envelope round trip", () => {
  const ks = testKeyset();
  const payload = new TextEncoder().encode(`{"requestId":"req_1"}`);

  const envelopeJSON = signEnvelope(ks, payload);
  const got = verifyEnvelope(envelopeJSON, [publicKeyset(ks)]);

  assert.deepEqual(Buffer.from(got), Buffer.from(payload));
});

test("keyset carries both algorithms", () => {
  const ks = testKeyset();

  assert.equal(ks.keys.length, KEYSET_ALGS.length);
  KEYSET_ALGS.forEach((alg, i) => {
    assert.equal(ks.keys[i].alg, alg);
    assert.equal(ks.keys[i].idx, i);
  });
});

// What the shared keygen vectors rely on: one seed expands to one public key,
// in every implementation of every language.
test("seed derivation is deterministic", () => {
  for (const [alg, len] of [
    [ALG_ED25519, 32],
    [ALG_ML_DSA_65, 32],
  ] as const) {
    const seed = new Uint8Array(len).fill(7);
    const first = keyFromSeed(alg, seed);
    const second = keyFromSeed(alg, seed);
    assert.deepEqual(Buffer.from(first), Buffer.from(second), alg);
    assert.ok(first.length > 0, alg);
  }
});

// A keyset object handed to console.log or an uncareful JSON.stringify call
// must not spill its private key material.
test("generateKeyset redacts private key material from JSON.stringify", () => {
  const ks = testKeyset();
  assert.ok(!JSON.stringify(ks).includes('"priv"'));
});

// Pins the persisted shape. SPs already hold serialized keysets in this form,
// and ML-DSA private keys cannot be reduced back to a seed, so a field rename
// here strands every existing keyset.
test("keyset JSON is backward compatible", () => {
  const ks = testKeyset();
  const stored = signingKeysetToJSON(ks) as {
    keysetId: string;
    keys: { idx: number; alg: string; pub: string; priv: string }[];
  };

  assert.equal(stored.keys.length, KEYSET_ALGS.length);
  stored.keys.forEach((k, i) => {
    assert.equal(k.alg, KEYSET_ALGS[i]);
    assert.equal(k.idx, i);
    assert.ok(k.pub.length > 0 && k.priv.length > 0);
  });

  // A stored keyset must come back able to sign.
  const restored = signingKeysetFromJSON(stored);
  const envelopeJSON = signEnvelope(restored, new TextEncoder().encode(`{"a":1}`));
  assert.ok(verifyEnvelope(envelopeJSON, [publicKeyset(restored)]));
});

test("keyset round-trips through JSON.stringify/parse and still signs", () => {
  const ks = testKeyset();
  const json = JSON.stringify(signingKeysetToJSON(ks));
  const restored = signingKeysetFromJSON(JSON.parse(json));

  const envelopeJSON = signEnvelope(restored, new TextEncoder().encode(`{"a":1}`));
  assert.ok(verifyEnvelope(envelopeJSON, [publicKeyset(restored)]));
});

test("signingKeysetFromJSON rejects a malformed object", () => {
  for (const bad of [null, {}, { keysetId: "ks" }, { keysetId: "ks", keys: [{}] }]) {
    assert.throws(() => signingKeysetFromJSON(bad), /stepauth:/);
  }
});

test("verify rejects a tampered payload", () => {
  const ks = testKeyset();
  const envelopeJSON = signEnvelope(ks, new TextEncoder().encode(`{"requestId":"req_1"}`));

  const tampered = reEncode(envelopeJSON, (env) => {
    env.payload = b64(`{"requestId":"req_2"}`);
  });

  assert.throws(
    () => verifyEnvelope(tampered, [publicKeyset(ks)]),
    InvalidSignatureError,
  );
});

test("verify rejects an unresolvable keysetId", () => {
  const ks = testKeyset();
  const envelopeJSON = signEnvelope(ks, new TextEncoder().encode("{}"));

  const other = publicKeyset(ks);
  other.keysetId = "ks_someone_else";

  assert.throws(() => verifyEnvelope(envelopeJSON, [other]), InvalidSignatureError);
});

// The vacuous all-of: with no components every check passes trivially and any
// payload verifies. signatures is also empty so the count check (0 === 0)
// clears without exercising the guard under test.
test("verify rejects a zero-key keyset", () => {
  const envelopeJSON = JSON.stringify({
    payload: b64("{}"),
    signature: { keysetId: "ks_test", signatures: [] },
  });

  assert.throws(
    () => verifyEnvelope(envelopeJSON, [{ keysetId: "ks_test", keys: [] }]),
    InvalidSignatureError,
  );
});

test("verify rejects a signature count mismatch", () => {
  const ks = testKeyset();
  const envelopeJSON = signEnvelope(ks, new TextEncoder().encode("{}"));

  const tooFew = reEncode(envelopeJSON, (env) => {
    env.signature.signatures = env.signature.signatures.slice(0, 1);
  });
  const tooMany = reEncode(envelopeJSON, (env) => {
    env.signature.signatures = [...env.signature.signatures, "AA=="];
  });

  for (const [name, mutated] of [
    ["too few", tooFew],
    ["too many", tooMany],
  ] as const) {
    assert.throws(
      () => verifyEnvelope(mutated, [publicKeyset(ks)]),
      InvalidSignatureError,
      name,
    );
  }
});

// The hybrid downgrade check. An implementation that stops at the first valid
// signature, or only checks the classical half, passes every other test in this
// file and fails this one.
test("verify rejects a single bad component", () => {
  const ks = testKeyset();
  const payload = new TextEncoder().encode(`{"requestId":"req_1"}`);
  const envelopeJSON = signEnvelope(ks, payload);

  // A signature valid for other bytes: structurally sound, wrong message.
  const decoy = JSON.parse(
    signEnvelope(ks, new TextEncoder().encode(`{"requestId":"req_other"}`)),
  ) as Envelope;

  KEYSET_ALGS.forEach((alg, idx) => {
    const swapped = reEncode(envelopeJSON, (env) => {
      env.signature.signatures[idx] = decoy.signature.signatures[idx]!;
    });
    assert.throws(
      () => verifyEnvelope(swapped, [publicKeyset(ks)]),
      InvalidSignatureError,
      `only the ${alg} component was wrong`,
    );
  });
});

// The hybrid pair is mandatory in index order: a keyset missing a component,
// or repeating one, must never sign or verify.
test("signEnvelope and verifyEnvelope reject a keyset that isn't the exact v1 pair in order", () => {
  const ks = testKeyset();
  const classicalOnly = { keysetId: ks.keysetId, keys: [ks.keys[0]] };
  const duplicated = { keysetId: ks.keysetId, keys: [ks.keys[0], ks.keys[0]] };

  for (const bad of [classicalOnly, duplicated]) {
    assert.throws(() => signEnvelope(bad, new TextEncoder().encode("{}")));
  }

  const validEnvelope = signEnvelope(ks, new TextEncoder().encode("{}"));
  const badKeysets = [publicKeyset(classicalOnly), publicKeyset(duplicated)];
  for (const keyset of badKeysets) {
    assert.throws(() => verifyEnvelope(validEnvelope, [keyset]), InvalidSignatureError);
  }
});

test("decoding a payload does not verify it", () => {
  const ks = testKeyset();
  const envelopeJSON = signEnvelope(ks, new TextEncoder().encode(`{"requestId":"req_1"}`));

  const tampered = reEncode(envelopeJSON, (env) => {
    env.payload = b64(`{"requestId":"forged"}`);
  });

  // Routing needs the payload before the keyset is known, so this must decode
  // what verifyEnvelope would reject.
  const got = decodeEnvelopePayload(tampered);
  assert.equal(new TextDecoder().decode(got), `{"requestId":"forged"}`);
});

test("verify rejects lenient base64 the hub would reject", () => {
  const ks = testKeyset();
  const envelopeJSON = signEnvelope(ks, new TextEncoder().encode("{}"));

  for (const mutate of [
    (env: Envelope) => {
      env.payload = env.payload.replace(/=+$/, ""); // padding stripped
    },
    (env: Envelope) => {
      env.payload = env.payload + "@@@";
    },
    (env: Envelope) => {
      env.payload = env.payload.slice(0, 2) + " " + env.payload.slice(2);
    },
    (env: Envelope) => {
      env.payload = "q83v_-7dqw"; // base64url alphabet
    },
  ]) {
    const mutated = reEncode(envelopeJSON, mutate);
    assert.throws(() => verifyEnvelope(mutated, [publicKeyset(ks)]), InvalidSignatureError);
  }
});

test("verify accepts base64 forms Go's StdEncoding accepts", () => {
  const ks = testKeyset();

  // Line-wrapped: decoding ignores embedded CR/LF, so the signed bytes are
  // unchanged and the signature still verifies.
  const wrapped = signEnvelope(ks, new TextEncoder().encode(`{"requestId":"req_1"}`));
  const lineWrapped = reEncode(wrapped, (env) => {
    env.payload = env.payload.slice(0, 4) + "\n" + env.payload.slice(4);
  });
  assert.doesNotThrow(() => verifyEnvelope(lineWrapped, [publicKeyset(ks)]));

  // "AB==" has non-canonical unused trailing bits but decodes to the same
  // single zero byte as the canonical "AA==" this payload was signed as.
  const zeroByte = signEnvelope(ks, new Uint8Array([0]));
  const noncanonical = reEncode(zeroByte, (env) => {
    env.payload = "AB==";
  });
  assert.doesNotThrow(() => verifyEnvelope(noncanonical, [publicKeyset(ks)]));
});

test("decodeEnvelopePayload accepts base64 forms Go's StdEncoding accepts", () => {
  assert.equal(
    new TextDecoder().decode(decodeEnvelopePayload(JSON.stringify({ payload: "e3\n0=" }))),
    "{}",
  );
  assert.deepEqual(Buffer.from(decodeEnvelopePayload(JSON.stringify({ payload: "AB==" }))), Buffer.from([0]));
});

test("decodeEnvelopePayload rejects base64 forms Go's StdEncoding rejects", () => {
  for (const payload of ["q83v_-7dqw", "e30", "e30=@@@"]) {
    assert.throws(() => decodeEnvelopePayload(JSON.stringify({ payload })), EnvelopeFormatError);
  }
});

test("verify rejects a structurally malformed envelope with InvalidSignatureError, not a raw TypeError", () => {
  const ks = testKeyset();
  const keysets = [publicKeyset(ks)];

  const badPayloads = [
    { signature: { keysetId: "ks_test", signatures: ["AA=="] } }, // payload absent
    { payload: null, signature: { keysetId: "ks_test", signatures: ["AA=="] } },
    { payload: 1, signature: { keysetId: "ks_test", signatures: ["AA=="] } },
    { payload: {}, signature: { keysetId: "ks_test", signatures: ["AA=="] } },
    { payload: "AA==", signature: { keysetId: "ks_test", signatures: [null, "AA=="] } },
    { payload: "AA==", signature: { keysetId: "ks_test", signatures: [1, "AA=="] } },
    { payload: "AA==" }, // signature absent
    { payload: "AA==", signature: null },
    { payload: "AA==", signature: { keysetId: "ks_test", signatures: ["AA==", "AA=="] } },
  ];

  for (const bad of badPayloads) {
    assert.throws(
      () => verifyEnvelope(JSON.stringify(bad), keysets),
      InvalidSignatureError,
    );
  }

  // A resolvable keyset with keys: null must also reject cleanly.
  const nullKeysKeysets = [{ keysetId: "ks_test", keys: null }] as unknown as Parameters<
    typeof verifyEnvelope
  >[1];
  assert.throws(
    () =>
      verifyEnvelope(
        JSON.stringify({ payload: "AA==", signature: { keysetId: "ks_test", signatures: [] } }),
        nullKeysKeysets,
      ),
    InvalidSignatureError,
  );
});

test("decodeEnvelopePayload throws EnvelopeFormatError on malformed input, never InvalidSignatureError", () => {
  for (const bad of ['{', '{"payload":null}', '{"signature":{}}', "null"]) {
    assert.throws(() => decodeEnvelopePayload(bad), EnvelopeFormatError);
  }
});

// alg "none" (or any unrecognized algorithm) must fail closed.
test("verifyComponent rejects an unsupported algorithm", () => {
  assert.equal(
    verifyComponent("none", new Uint8Array(32), new Uint8Array([1]), new Uint8Array([2])),
    false,
  );
});

test("envelope pins the base64 alphabet and the JSON key names", () => {
  const ks = generateKeyset("ks_wire");
  // Encodes to "/++++Q==" in the standard alphabet and "_----Q==" in
  // base64url, so the two are distinguishable here where short ASCII
  // payloads make them identical.
  const payload = new Uint8Array([0xff, 0xef, 0xbe, 0xfb, 0xff, 0x41]);
  const want = Buffer.from(payload).toString("base64");

  const env = JSON.parse(signEnvelope(ks, payload));
  assert.deepEqual(Object.keys(env).sort(), ["payload", "signature"]);
  assert.deepEqual(Object.keys(env.signature).sort(), ["keysetId", "signatures"]);
  assert.equal(env.payload, want);
  assert.equal(env.signature.keysetId, "ks_wire");
  assert.equal(env.signature.signatures.length, KEYSET_ALGS.length);
});

test("ML-DSA signing is deterministic", () => {
  const ks = testKeyset();
  const mldsaKey = ks.keys.find((k) => k.alg === ALG_ML_DSA_65)!;
  const msg = new TextEncoder().encode("hello");

  const sig1 = signComponent(mldsaKey, msg);
  const sig2 = signComponent(mldsaKey, msg);

  assert.deepEqual(Buffer.from(sig1), Buffer.from(sig2));
});
