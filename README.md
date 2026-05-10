# splitsecure/apis

Protocol Buffer and [Connect-RPC](https://connectrpc.com/) definitions for
the SplitSecure public APIs.

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
[`@bufbuild/protobuf`](https://github.com/bufbuild/protobuf-es) v2 and
[`@connectrpc/connect`](https://github.com/connectrpc/connect-es) v2.
Vendor the `gen/es/proto/` tree directly or publish your own npm package
from it.

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
