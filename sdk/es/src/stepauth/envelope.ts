import {
  EnvelopeFormatError,
  InvalidSignatureError,
  signComponent,
  validateKeyset,
  verifyComponent,
  type Keyset,
  type SigningKeyset,
} from "./crypto.js";

/**
 * A keyset signature: the signing keyset's id plus one signature per component
 * key, ordered by keyset index.
 */
export interface Signature {
  keysetId: string;
  signatures: string[];
}

/**
 * The signed wrapper every protocol message travels in. `payload` is base64 of
 * the raw message bytes, and signatures cover those exact bytes.
 */
export interface Envelope {
  payload: string;
  signature: Signature;
}

// Decode base64 the way Go's base64.StdEncoding.DecodeString does: skip CR/LF
// anywhere, require the standard alphabet plus correct padding, but tolerate
// non-canonical unused trailing bits ("AB==") the way Go does. A bare
// Buffer.from is far laxer (accepts base64url and unpadded input); a naive
// re-encode-and-compare is far stricter (rejects line wraps and "AB==").
function stdBase64(s: unknown): Uint8Array | undefined {
  if (typeof s !== "string") return undefined;
  const compact = s.replace(/[\r\n]/g, "");
  if (compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) {
    return undefined;
  }
  return new Uint8Array(Buffer.from(compact, "base64"));
}

function strictBase64(s: unknown): Uint8Array {
  const bytes = stdBase64(s);
  if (bytes === undefined) throw new InvalidSignatureError();
  return bytes;
}

/**
 * Sign the payload with every key in the keyset and return the marshaled
 * envelope. Signatures cover the payload bytes exactly as they will be
 * transmitted; nothing between here and the wire may reserialize them.
 */
export function signEnvelope(ks: SigningKeyset, payload: Uint8Array): string {
  if (!ks || ks.keys.length === 0) throw new Error("stepauth: signing keyset is empty");
  if (!ks.keysetId) throw new Error("stepauth: signing keyset has no keysetId");
  validateKeyset(ks);

  const envelope: Envelope = {
    payload: Buffer.from(payload).toString("base64"),
    signature: {
      keysetId: ks.keysetId,
      signatures: ks.keys.map((key) =>
        Buffer.from(signComponent(key, payload)).toString("base64"),
      ),
    },
  };
  return JSON.stringify(envelope);
}

/**
 * Resolve the envelope's keysetId against the signer's active keysets and
 * verify all-of, returning the decoded payload. Every failure throws
 * InvalidSignatureError.
 */
export function verifyEnvelope(envelopeJSON: string, keysets: Keyset[]): Uint8Array {
  let env: Envelope;
  try {
    env = JSON.parse(envelopeJSON) as Envelope;
  } catch {
    throw new InvalidSignatureError();
  }
  if (typeof env?.payload !== "string") throw new InvalidSignatureError();
  if (!Array.isArray(env?.signature?.signatures)) throw new InvalidSignatureError();
  if (env.signature.signatures.some((s) => typeof s !== "string")) {
    throw new InvalidSignatureError();
  }

  const keyset = keysets.find((k) => k.keysetId === env.signature.keysetId);
  if (!keyset || !Array.isArray(keyset.keys)) throw new InvalidSignatureError();
  // All-of over a partial keyset verifies against whatever it happens to
  // carry, so a keyset missing a component (or degraded to zero) must reject.
  try {
    validateKeyset(keyset);
  } catch {
    throw new InvalidSignatureError();
  }
  if (env.signature.signatures.length !== keyset.keys.length) {
    throw new InvalidSignatureError();
  }

  const payload = strictBase64(env.payload);

  keyset.keys.forEach((kk, i) => {
    const sig = strictBase64(env.signature.signatures[i]);
    const pub = strictBase64(kk.pub);
    if (!verifyComponent(kk.alg, pub, payload, sig)) {
      throw new InvalidSignatureError();
    }
  });

  return payload;
}

/**
 * Base64-decode a payload WITHOUT verifying the signature. Only for routing a
 * message to the state needed to verify it; the result is untrusted until
 * verifyEnvelope has run.
 */
export function decodeEnvelopePayload(envelopeJSON: string): Uint8Array {
  let env: Envelope;
  try {
    env = JSON.parse(envelopeJSON) as Envelope;
  } catch {
    throw new EnvelopeFormatError();
  }
  const payload = stdBase64(env?.payload);
  if (payload === undefined) throw new EnvelopeFormatError();
  return payload;
}
