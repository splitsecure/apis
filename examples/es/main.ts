// A minimal service provider: establishes a signing identity, writes the
// metadata a hub administrator registers, and produces a signed authorization
// request.
//
//   pnpm start
//
// Artifacts land in ./out. Re-running reuses the existing keyset rather than
// minting a new one, because a new keyset means registering with the hub again.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

import {
  generateKeyset,
  publicKeyset,
  signEnvelope,
  signingKeysetFromJSON,
  signingKeysetToJSON,
  verifyEnvelope,
  type SigningKeyset,
} from "@splitsecure/sdk/stepauth";

const OUT_DIR = "out";
const KEYSET_FILE = "out/sp-keyset.json"; // private: never leaves the SP
const METADATA_FILE = "out/sp-metadata.json"; // public: handed to a hub administrator
const ENVELOPE_FILE = "out/request-envelope.json";

const SP_ENTITY = "sp.example.com";
const HUB_ENTITY = "acme.hub.example.com";
const CALLBACK_URL = "https://sp.example.com/stepauth/callback";

/** Read the persisted signing identity, minting one on first run. */
function establishIdentity(): SigningKeyset {
  try {
    const keyset = signingKeysetFromJSON(JSON.parse(readFileSync(KEYSET_FILE, "utf8")));
    console.log(`${KEYSET_FILE}  loaded existing identity "${keyset.keysetId}"`);
    return keyset;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  const minted = generateKeyset(`ks_${stamp}`);

  writeFileSync(KEYSET_FILE, `${JSON.stringify(signingKeysetToJSON(minted), null, 2)}\n`, {
    mode: 0o600,
  });
  console.log(`${KEYSET_FILE}  minted identity "${minted.keysetId}", keep this private`);
  return minted;
}

/** Build an authorization request and sign it into an envelope. */
function signRequest(ks: SigningKeyset): string {
  const now = new Date();
  const request = {
    requestId: `req_${now.toISOString().replace(/\D/g, "").slice(0, 14)}`,
    senderId: SP_ENTITY,
    recipientId: HUB_ENTITY,
    timestamp: now.toISOString(),
    expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString(),
    principal: { subject: "email:operator@example.com" },
    action: {
      type: "com.example.database.drop",
      category: "data.delete",
      name: "Drop the production database",
      summary:
        "Permanently deletes the production database and every backup older than 24 hours.",
    },
  };

  return signEnvelope(ks, new TextEncoder().encode(JSON.stringify(request)));
}

mkdirSync(OUT_DIR, { recursive: true });

const keyset = establishIdentity();

const metadata = {
  entity: SP_ENTITY,
  keysets: [publicKeyset(keyset)],
  callbackUrl: CALLBACK_URL,
};
writeFileSync(METADATA_FILE, `${JSON.stringify(metadata, null, 2)}\n`);
console.log(`${METADATA_FILE}  register this with the hub`);

const envelope = signRequest(keyset);
writeFileSync(ENVELOPE_FILE, envelope, { mode: 0o600 });
console.log(`${ENVELOPE_FILE}  ${envelope.length} bytes, POST this to the hub`);

// Retain the payload bytes exactly as signed. The hub's decision carries a
// digest over them, and re-encoding the request would make that digest
// unverifiable.
const payload = verifyEnvelope(envelope, [publicKeyset(keyset)]);
console.log(
  `\nsigned payload verifies, ${payload.length} bytes to retain for the decision digest`,
);
