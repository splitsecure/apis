# splitsecure/apis

The SplitSecure public API surface: Protocol Buffer and
[Connect-RPC](https://connectrpc.com/) definitions under `proto/`, and the
SplitSecure SDK under `sdk/`.

This repository is the source of truth for the wire format. Generated
Go and TypeScript bindings are checked in under `gen/` so that
downstream consumers can depend on this repo directly without running a
code generator.

## Services

| Package | Service | Purpose |
| --- | --- | --- |
| `splitsecure.enclave.v1` | `EnclaveService` | Invoke and explain enclave applications. |
| `splitsecure.enclaveroundtrip.v1` | `EnclaveRoundtripService` | Companion-to-enclave request/response transport, with streaming and long-poll variants. |
| `splitsecure.proposals.v1` | `ProposalsService` | Threshold-vote a proposal to completion; list, watch and inspect proposal state. |
| `splitsecure.conveniencestore.v1` | `ConvenienceStoreService` | SAML2 identity-provider and service-provider resource management. |

The remaining packages (`bottle`, `delegationgraph`, `hybridkeyset`,
`keys`, `saml2`, `teamresource`, `attestation`, `requestsigning`,
`audit_observation_receipt`, `graphsigned`) carry the message types used
by the services above.

## Using the generated code

### Go

```bash
go get github.com/splitsecure/apis@latest
```

```go
import (
    enclavev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclave/v1"
    enclavev1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclave/v1/enclavev1connect"
)
```

### TypeScript

The TypeScript bindings are emitted under `gen/es/proto/` and target
[`@bufbuild/protobuf`](https://github.com/bufbuild/protobuf-es) v2. They are
packaged as `@splitsecure/proto`, with one subpath per generated file:

```ts
import { TeamBaseInfoSchema } from "@splitsecure/proto/splitsecure/teamresource/v1/team_base_info_pb";
```

`@bufbuild/protobuf` is a peer dependency, so one copy is shared with whatever
else in the consumer uses it.

## SplitSecure SDK

`sdk/` holds the SplitSecure SDK: client libraries for the StepAuth
service-provider protocol.

StepAuth is a JSON protocol rather than a Protocol Buffer one, and its
signatures and request digest cover the raw payload bytes with no
canonicalization. These libraries are therefore written directly against the
wire rather than emitted from `proto/`. The languages are meant to be kept in
step by a shared conformance vector suite generated from the hub; that suite
is not committed yet.

One subdirectory per service: each is a separate Go module or TypeScript
package, so its types cannot collide with another's.

| Language | Import |
| --- | --- |
| Go | `github.com/splitsecure/apis/sdk/go/stepauth` |
| TypeScript | `@splitsecure/sdk/stepauth` |

A service provider is both a client of a hub and a server for that hub's
decision callbacks, so the SDK spans both directions: signing and submitting
requests outbound, and verifying signed decisions inbound.

`examples/` holds one runnable app per supported language. Each establishes a
signing identity, writes the metadata document a hub administrator registers,
and produces a signed authorization request under `out/`.

```bash
(cd examples/go && go run .)
(cd examples/es && pnpm install && pnpm start)
```

## Regenerating

```bash
pnpm install --frozen-lockfile
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest
./bufgen.sh
```

`bufgen.sh` runs `buf format`, `buf lint`, and `buf generate`. CI
re-runs the same script on every push and fails if the result drifts
from what is committed.

## License

[MIT](./LICENSE)
