# StepAuth service provider, in TypeScript

A minimal service provider. It establishes a signing identity, writes the
metadata document a hub administrator registers, and produces a signed
authorization request.

```bash
pnpm install
pnpm start
```

## What it does

**1. Establishes a signing identity.** The example mints a keyset on the first
run and writes it to `out/sp-keyset.json`. Every later run loads that file
instead. A keyset is the identity of the service provider. If you replace it,
you must register again with every hub that trusts you.

The keyset holds private material. It never leaves the service provider.

Each keyset carries two component keys, ed25519 and ml-dsa-65. Both keys sign
every message, and both must verify. Breaking one algorithm is not enough to
forge a signature.

**2. Writes the metadata a hub registers.** `out/sp-metadata.json` has the three
things a hub needs to register this service provider:

- The entity name
- The public half of the keyset, with the private material stripped
- The callback URL that receives decisions

An administrator registers this file with the hub. The hub then recognizes your
signatures.

**3. Signs an authorization request.** The request names the principal, the
action, and the hub that must decide. The example signs it into an envelope and
writes it to `out/request-envelope.json`. That envelope is the body a service
provider POSTs to the hub.

**4. Verifies its own envelope.** This step shows the verification path and
recovers the exact payload bytes. A real service provider verifies the *hub's*
decision instead, against the keysets in the hub's metadata document.

## Retaining the exact bytes

The signature covers the payload bytes exactly as transmitted, with no
canonicalization. The hub's decision includes a digest over those same bytes.

Retain those bytes verbatim. If you re-encode a request between the signature
and the send, the bytes change and the digest no longer verifies. The same is
true if you rebuild a request from parsed fields to check a decision against it.
The example prints the byte count it retains for this reason.

## Storing a keyset

`generateKeyset` returns `Uint8Array` fields. These fields do not survive
`JSON.stringify` intact. The example converts them to base64 on the way out and
back on the way in. This is the shape the Go SDK reads and writes, so a keyset
stored by one language loads in the other.

## What is not here yet

This example does not submit to a hub, read the approver directory, or receive
decision callbacks. The SDK covers all three.
