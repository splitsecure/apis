import {
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

/** Signature-algorithm wire names, appearing verbatim as a component's alg. */
export const ALG_ED25519 = "ed25519";
export const ALG_ML_DSA_65 = "ml-dsa-65";

/**
 * The v1 hybrid pair in index order. Verification is all-of: every component
 * must verify, so the pair degrades no further than its stronger half if
 * either primitive is broken.
 */
export const KEYSET_ALGS = [ALG_ED25519, ALG_ML_DSA_65] as const;

/** All-of over a partial keyset is all-of over whatever it happens to
 * carry, so a keyset missing a component downgrades verification silently. */
export function validateKeyset(ks: { keysetId: string; keys: { alg: string }[] }): void {
  if (ks.keys?.length !== KEYSET_ALGS.length || ks.keys.some((k, i) => k.alg !== KEYSET_ALGS[i])) {
    throw new Error(`stepauth: keyset "${ks.keysetId}" must carry the v1 algorithms in order`);
  }
}

/** Any envelope verification failure. The cause is deliberately not
 * distinguished: a caller that can tell "wrong keyset" from "bad signature"
 * learns something an attacker also learns. */
export class InvalidSignatureError extends Error {
  constructor(message = "stepauth: invalid signature") {
    super(message);
    this.name = "InvalidSignatureError";
  }
}

/** An envelope that is malformed independent of signature verification. */
export class EnvelopeFormatError extends Error {
  constructor(message = "stepauth: malformed envelope") {
    super(message);
    this.name = "EnvelopeFormatError";
  }
}

/** One component of a keyset, holding private material. `priv` is the
 * algorithm's expanded private key. */
export interface SigningKey {
  idx: number;
  alg: string;
  pub: Uint8Array;
  priv: Uint8Array;
}

/** An SP's signing identity, named by an opaque immutable id. */
export interface SigningKeyset {
  keysetId: string;
  keys: SigningKey[];
}

/** One component public key as published in a metadata document. */
export interface KeysetKey {
  idx: number;
  alg: string;
  pub: string;
}

/** The public wire form of a signing identity. */
export interface Keyset {
  keysetId: string;
  keys: KeysetKey[];
}

// DER prefix for an Ed25519 public key (OID 1.3.101.112).
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// DER prefix for an Ed25519 private key (OID 1.3.101.112, wrapped OCTET STRING).
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const ED25519_SEED_LEN = 32;
const ED25519_PUB_LEN = 32;
const ED25519_PRIV_LEN = 64; // seed || public, matching Go's ed25519.PrivateKey
const ML_DSA_65_SEED_LEN = 32;
const ML_DSA_65_PRIV_LEN = 4032;

function rawToPublicKey(raw: Uint8Array): KeyObject {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function seedToPrivateKey(seed: Uint8Array): KeyObject {
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function rawPublicBytes(key: KeyObject): Uint8Array {
  const der = key.export({ format: "der", type: "spki" });
  return new Uint8Array(der.subarray(ED25519_SPKI_PREFIX.length));
}

/** Attach non-enumerable log/serialize redaction so a keyset never leaks
 * private key material through console.log or JSON.stringify. */
function redacted(ks: SigningKeyset): SigningKeyset {
  const summary = () => ({ keysetId: ks.keysetId, keys: ks.keys.length });
  Object.defineProperty(ks, "toJSON", { value: summary, enumerable: false });
  Object.defineProperty(ks, Symbol.for("nodejs.util.inspect.custom"), {
    value: summary,
    enumerable: false,
  });
  return ks;
}

/** Mint a keyset carrying one fresh component per v1 algorithm. */
export function generateKeyset(keysetId: string): SigningKeyset {
  if (!keysetId) throw new Error("stepauth: keysetId is required");

  const keys: SigningKey[] = KEYSET_ALGS.map((alg, idx) => {
    if (alg === ALG_ED25519) {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const pub = rawPublicBytes(publicKey);
      const seed = new Uint8Array(
        privateKey
          .export({ format: "der", type: "pkcs8" })
          .subarray(ED25519_PKCS8_PREFIX.length),
      );
      const priv = new Uint8Array(ED25519_PRIV_LEN);
      priv.set(seed, 0);
      priv.set(pub, ED25519_SEED_LEN);
      return { idx, alg, pub, priv };
    }

    const { publicKey, secretKey } = ml_dsa65.keygen();
    return { idx, alg, pub: publicKey, priv: secretKey };
  });

  return redacted({ keysetId, keys });
}

/** Expand an algorithm seed into its public key. Both v1 algorithms derive
 * deterministically from a seed. */
export function keyFromSeed(alg: string, seed: Uint8Array): Uint8Array {
  if (alg === ALG_ED25519) {
    if (seed.length !== ED25519_SEED_LEN) {
      throw new Error(
        `stepauth: ed25519 seed is ${seed.length} bytes, want ${ED25519_SEED_LEN}`,
      );
    }
    return rawPublicBytes(createPublicKey(seedToPrivateKey(seed)));
  }
  if (alg === ALG_ML_DSA_65) {
    if (seed.length !== ML_DSA_65_SEED_LEN) {
      throw new Error(
        `stepauth: ml-dsa-65 seed is ${seed.length} bytes, want ${ML_DSA_65_SEED_LEN}`,
      );
    }
    return ml_dsa65.keygen(seed).publicKey;
  }
  throw new Error(`stepauth: unsupported algorithm ${alg}`);
}

/** The metadata form of the keyset, private material stripped. */
export function publicKeyset(ks: SigningKeyset): Keyset {
  return {
    keysetId: ks.keysetId,
    keys: ks.keys.map((k) => ({
      idx: k.idx,
      alg: k.alg,
      pub: Buffer.from(k.pub).toString("base64"),
    })),
  };
}

/** Serialize a signing keyset to its wire JSON shape, byte-for-byte what Go's
 * json.Marshal(*SigningKeyset) produces: base64 pub/priv, no typed arrays. */
export function signingKeysetToJSON(ks: SigningKeyset): unknown {
  return {
    keysetId: ks.keysetId,
    keys: ks.keys.map((k) => ({
      idx: k.idx,
      alg: k.alg,
      pub: Buffer.from(k.pub).toString("base64"),
      priv: Buffer.from(k.priv).toString("base64"),
    })),
  };
}

/** Parse a signing keyset from the shape signingKeysetToJSON produces. */
export function signingKeysetFromJSON(obj: unknown): SigningKeyset {
  const o = obj as
    | { keysetId?: unknown; keys?: unknown }
    | null
    | undefined;
  if (typeof o?.keysetId !== "string" || !Array.isArray(o.keys)) {
    throw new Error("stepauth: malformed signing keyset JSON");
  }
  const keys: SigningKey[] = o.keys.map((k: unknown) => {
    const key = k as
      | { idx?: unknown; alg?: unknown; pub?: unknown; priv?: unknown }
      | null
      | undefined;
    if (
      typeof key?.idx !== "number" ||
      typeof key.alg !== "string" ||
      typeof key.pub !== "string" ||
      typeof key.priv !== "string"
    ) {
      throw new Error("stepauth: malformed signing keyset JSON");
    }
    return {
      idx: key.idx,
      alg: key.alg,
      pub: new Uint8Array(Buffer.from(key.pub, "base64")),
      priv: new Uint8Array(Buffer.from(key.priv, "base64")),
    };
  });
  return redacted({ keysetId: o.keysetId, keys });
}

/** Sign the raw message bytes with one component's private key. */
export function signComponent(key: SigningKey, msg: Uint8Array): Uint8Array {
  if (key.alg === ALG_ED25519) {
    if (key.priv.length !== ED25519_PRIV_LEN) {
      throw new Error(
        `stepauth: ed25519 private key is ${key.priv.length} bytes, want ${ED25519_PRIV_LEN}`,
      );
    }
    const seed = key.priv.subarray(0, ED25519_SEED_LEN);
    return new Uint8Array(nodeSign(null, Buffer.from(msg), seedToPrivateKey(seed)));
  }
  if (key.alg === ALG_ML_DSA_65) {
    if (key.priv.length !== ML_DSA_65_PRIV_LEN) {
      throw new Error(
        `stepauth: ml-dsa-65 private key is ${key.priv.length} bytes, want ${ML_DSA_65_PRIV_LEN}`,
      );
    }
    // Deterministic to match the hub, and to keep signatures comparable across languages.
    return ml_dsa65.sign(msg, key.priv, { extraEntropy: false });
  }
  throw new Error(`stepauth: unsupported algorithm ${key.alg}`);
}

/** Check one component's signature over the raw message bytes. */
export function verifyComponent(
  alg: string,
  pub: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
): boolean {
  try {
    if (alg === ALG_ED25519) {
      if (pub.length !== ED25519_PUB_LEN) return false;
      return nodeVerify(null, Buffer.from(msg), rawToPublicKey(pub), Buffer.from(sig));
    }
    if (alg === ALG_ML_DSA_65) {
      return ml_dsa65.verify(sig, msg, pub);
    }
  } catch {
    return false;
  }
  return false;
}
