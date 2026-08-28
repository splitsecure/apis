# @splitsecure/sdk

Client for the StepAuth service-provider protocol. A service provider asks a
hub to get a privileged action approved by a human. Every message is a signed
envelope. There is no session and no polling.

```bash
npm install @splitsecure/sdk
```

```ts
import { generateKeyset, sendRequest, verifyDecision } from "@splitsecure/sdk/stepauth";
```

The SDK covers envelope signing and verification over the hybrid ed25519 and
ml-dsa-65 keyset, request submission, the approver directory, and the decision
callback handler.

Two rules the SDK enforces and a caller must not defeat. The envelope is signed
once, and every retry sends those exact bytes, because the decision's digest
covers them. The request payload must be retained verbatim until the decision
arrives.

Node 22 or later. Runnable examples live in `examples/es` in the
[repository](https://github.com/splitsecure/apis).

MIT.
