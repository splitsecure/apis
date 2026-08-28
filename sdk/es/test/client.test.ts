import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash } from "node:crypto";

import {
  generateKeyset,
  publicKeyset,
  signEnvelope,
  entry,
  group,
  ProtocolError,
  validateConfig,
  sendRequest,
  verifyDecision,
  queryDirectory,
  TransportError,
  SenderMismatchError,
  RecipientMismatchError,
  DigestMismatchError,
  type Config,
  type HubEntry,
  type SendRequestInput,
  type Decision,
} from "../src/stepauth/index.js";

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

/** A throwaway local hub: routes requests to a handler and records the raw
 * body of every request it received, in order. Registers its own cleanup on
 * t, so a test that throws before its trailing close() still shuts the
 * server down instead of hanging the runner. */
function startHub(
  t: TestContext,
  handle: (req: IncomingMessage, body: Buffer, res: ServerResponse) => void,
): {
  url: string;
  bodies: Buffer[];
} {
  const bodies: Buffer[] = [];
  const server = createServer((req, res) => {
    void readBody(req).then((body) => {
      bodies.push(body);
      handle(req, body, res);
    });
  });
  server.listen(0);
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    bodies,
  };
}

function writeJSON(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function testRequest(): SendRequestInput {
  return {
    principal: { subject: "email:a@b.com" },
    action: { type: "acme.widget.delete", category: "data.delete", summary: "Delete widget" },
  };
}

function testConfig(hubURL: string, hubEntity = "hub.example.com"): {
  cfg: Config;
  hub: HubEntry;
  hubKeyset: ReturnType<typeof generateKeyset>;
} {
  const spKeyset = generateKeyset("ks_sp");
  const hubKeyset = generateKeyset("ks_hub");
  const hub: HubEntry = {
    tag: "primary",
    default: true,
    metadata: { entity: hubEntity, keysets: [publicKeyset(hubKeyset)], host: hubURL },
  };
  const cfg: Config = {
    signingKeyset: spKeyset,
    sp: { entity: "sp.example.com" },
    hubs: [hub],
  };
  return { cfg, hub, hubKeyset };
}

// --- Config validation ---

test("validateConfig rejects zero or more than one default hub", () => {
  const { cfg, hub } = testConfig("http://x");
  cfg.hubs = [];
  assert.throws(() => validateConfig(cfg), /at least one hub/);

  cfg.hubs = [{ ...hub, default: true }, { ...hub, tag: "other", default: true }];
  assert.throws(() => validateConfig(cfg), /exactly one hub must be default/);
});

test("validateConfig rejects a hub missing host, entity, or keysets", () => {
  const { cfg, hub } = testConfig("http://x");
  cfg.hubs = [{ ...hub, metadata: { ...hub.metadata, host: "" } }];
  assert.throws(() => validateConfig(cfg), /host/);

  cfg.hubs = [{ ...hub, metadata: { ...hub.metadata, entity: "" } }];
  assert.throws(() => validateConfig(cfg), /entity/);

  cfg.hubs = [{ ...hub, metadata: { ...hub.metadata, keysets: [] } }];
  assert.throws(() => validateConfig(cfg), /keysets/);
});

// --- sendRequest: the freeze rule ---

test("a retried send transmits byte-identical bytes to the hub", async (t) => {
  let calls = 0;
  const hub = startHub(t, (_req, _body, res) => {
    calls++;
    if (calls === 1) {
      res.writeHead(503);
      res.end();
      return;
    }
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });

  const { cfg } = testConfig(hub.url);
  const { result } = await sendRequest(cfg, testRequest());

  assert.equal(hub.bodies.length, 2);
  assert.deepEqual(hub.bodies[0], hub.bodies[1]); // identical envelope bytes, not re-signed
  assert.equal(result.alreadySubmitted, undefined);
});

// --- sendRequest: 409 duplicate_request, attempt-number-dependent ---

test("a 409 on the first attempt is a real duplicate and rejects", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 409, { error: "duplicate_request", message: "requestId already submitted" });
  });

  const { cfg } = testConfig(hub.url);
  await assert.rejects(sendRequest(cfg, testRequest()), (err: unknown) => {
    assert.ok(err instanceof ProtocolError);
    assert.equal(err.code, "duplicate_request");
    return true;
  });
  assert.equal(hub.bodies.length, 1); // 409 is not retryable — this client never sent it before
});

test("a 409 after a dropped response is this client's own retry landing, and succeeds", async (t) => {
  let calls = 0;
  const hub = startHub(t, (_req, _body, res) => {
    calls++;
    if (calls === 1) {
      // Simulate the response never arriving: destroy the connection after the
      // hub has already durably received the body.
      res.destroy();
      return;
    }
    writeJSON(res, 409, { error: "duplicate_request", message: "requestId already submitted" });
  });

  const { cfg } = testConfig(hub.url);
  const { result } = await sendRequest(cfg, testRequest());

  assert.equal(calls, 2);
  assert.equal(result.alreadySubmitted, true);
  assert.equal(result.createdAt, undefined); // hub never re-reports it
});

test("a transport failure (dropped connection) is retried as a TransportError would allow", async (t) => {
  let calls = 0;
  const hub = startHub(t, (_req, _body, res) => {
    calls++;
    if (calls === 1) {
      res.destroy();
      return;
    }
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });

  const { cfg } = testConfig(hub.url);
  const { result } = await sendRequest(cfg, testRequest());

  assert.equal(calls, 2);
  assert.equal(result.status, "pending");
});

test("sendRequest gives up after MAX_ATTEMPTS retryable failures", async (t) => {
  let calls = 0;
  const hub = startHub(t, (_req, _body, res) => {
    calls++;
    res.writeHead(503);
    res.end();
  });

  const { cfg } = testConfig(hub.url);
  await assert.rejects(sendRequest(cfg, testRequest()));
  assert.equal(calls, 3);
});

test("a malformed_request (non-retryable) fails on the first attempt without retrying", async (t) => {
  let calls = 0;
  const hub = startHub(t, (_req, _body, res) => {
    calls++;
    writeJSON(res, 400, { error: "malformed_request", message: "bad" });
  });

  const { cfg } = testConfig(hub.url);
  await assert.rejects(sendRequest(cfg, testRequest()), ProtocolError);
  assert.equal(calls, 1);
});

test("a pure connection failure surfaces as TransportError once retries are exhausted", async () => {
  const cfg: Config = {
    signingKeyset: generateKeyset("ks_sp"),
    sp: { entity: "sp.example.com" },
    hubs: [
      {
        tag: "primary",
        default: true,
        // Nothing listens here: every attempt fails at the transport layer.
        metadata: { entity: "hub.example.com", keysets: [publicKeyset(generateKeyset("ks_hub"))], host: "http://127.0.0.1:1" },
      },
    ],
  };
  await assert.rejects(sendRequest(cfg, testRequest()), TransportError);
});

// --- verifyDecision: the four checks, each independently ---

function decisionFor(requestPayload: Uint8Array, overrides: Partial<Decision> = {}): Decision {
  const digest = createHash("sha256").update(requestPayload).digest("base64");
  return {
    requestId: "req_x",
    senderId: "hub.example.com",
    recipientId: "sp.example.com",
    decision: "approved",
    decidedAt: new Date().toISOString(),
    decidedBy: ["email:approver@b.com"],
    requestDigest: { algorithm: "sha256", value: digest },
    ...overrides,
  };
}

test("verifyDecision accepts a well-formed decision", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const { state } = await sendRequest(cfg, { ...testRequest(), requestId: "req_x" });

  const requestPayload = JSON.parse(hub.bodies[0].toString()).payload as string;
  const rawPayload = Buffer.from(requestPayload, "base64");
  const decision = decisionFor(rawPayload);
  const decisionEnvelope = signEnvelope(hubKeyset, new TextEncoder().encode(JSON.stringify(decision)));

  // PendingState carries exactly the bytes the hub received, so an SP that
  // stores it and reloads later still computes the digest the hub signed over.
  assert.equal(state.payload, requestPayload);
  assert.equal(state.hubEntity, "hub.example.com");

  const got = verifyDecision(cfg, decisionEnvelope, state);
  assert.equal(got.requestId, "req_x");
});

test("verifyDecision rejects an invalid signature", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg } = testConfig(hub.url);
  const { state } = await sendRequest(cfg, { ...testRequest(), requestId: "req_x" });

  const requestPayload = Buffer.from(JSON.parse(hub.bodies[0].toString()).payload as string, "base64");
  const decision = decisionFor(requestPayload);
  // Signed by a keyset the hub metadata never registered.
  const foreignKeyset = generateKeyset("ks_foreign");
  const decisionEnvelope = signEnvelope(foreignKeyset, new TextEncoder().encode(JSON.stringify(decision)));

  assert.throws(() => verifyDecision(cfg, decisionEnvelope, state));
});

test("verifyDecision rejects a senderId that doesn't match the hub recorded at send time", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const { state } = await sendRequest(cfg, { ...testRequest(), requestId: "req_x" });

  const requestPayload = Buffer.from(JSON.parse(hub.bodies[0].toString()).payload as string, "base64");
  const decision = decisionFor(requestPayload, { senderId: "some-other-hub.example.com" });
  const decisionEnvelope = signEnvelope(hubKeyset, new TextEncoder().encode(JSON.stringify(decision)));

  assert.throws(() => verifyDecision(cfg, decisionEnvelope, state), SenderMismatchError);
});

test("verifyDecision rejects a recipientId that isn't this SP", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const { state } = await sendRequest(cfg, { ...testRequest(), requestId: "req_x" });

  const requestPayload = Buffer.from(JSON.parse(hub.bodies[0].toString()).payload as string, "base64");
  const decision = decisionFor(requestPayload, { recipientId: "someone-else.example.com" });
  const decisionEnvelope = signEnvelope(hubKeyset, new TextEncoder().encode(JSON.stringify(decision)));

  assert.throws(() => verifyDecision(cfg, decisionEnvelope, state), RecipientMismatchError);
});

test("verifyDecision rejects a requestDigest that doesn't match the stored request", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const { state } = await sendRequest(cfg, { ...testRequest(), requestId: "req_x" });

  const decision = decisionFor(new TextEncoder().encode("some other request entirely"));
  const decisionEnvelope = signEnvelope(hubKeyset, new TextEncoder().encode(JSON.stringify(decision)));

  assert.throws(() => verifyDecision(cfg, decisionEnvelope, state), DigestMismatchError);
});

// --- approver directory ---

test("queryDirectory sends a signed body with requestUri bound to the endpoint, and pages via nextCursor", async (t) => {
  const seen: { requestUri: string; limit?: number; cursor?: string }[] = [];
  const hub = startHub(t, (_req, body, res) => {
    const query = JSON.parse(body.toString()) as { payload: string };
    const decoded = JSON.parse(Buffer.from(query.payload, "base64").toString()) as {
      requestUri: string;
      limit?: number;
      cursor?: string;
    };
    seen.push(decoded);
    if (!decoded.cursor) {
      writeJSON(res, 200, { items: [{ id: "email:a@b.com" }], nextCursor: "email:a@b.com" });
    } else {
      writeJSON(res, 200, { items: [{ id: "email:c@d.com" }] });
    }
  });

  const { cfg } = testConfig(hub.url);
  const page1 = await queryDirectory(cfg, "users", { limit: 1 });
  assert.equal(page1.nextCursor, "email:a@b.com");
  assert.equal(seen[0].requestUri, "/v1/users");
  assert.equal(seen[0].limit, 1);

  const page2 = await queryDirectory(cfg, "users", { cursor: page1.nextCursor });
  assert.equal(page2.items[0].id, "email:c@d.com");
  assert.equal(seen[1].cursor, "email:a@b.com");
});

test("queryDirectory signs the full path when the hub is mounted under a prefix", async (t) => {
  // The hub compares the signed requestUri against its own request path, so
  // signing a bare "/v1/users" reads as a replay against a different
  // resource. This stub rejects exactly as the hub does rather than trusting
  // whatever it is sent.
  const prefix = "/stepauth/org_123";
  const hub = startHub(t, (req, body, res) => {
    const { payload } = JSON.parse(body.toString()) as { payload: string };
    const { requestUri } = JSON.parse(Buffer.from(payload, "base64").toString()) as {
      requestUri: string;
    };
    if (requestUri !== req.url) {
      writeJSON(res, 403, { error: "wrong_recipient" });
      return;
    }
    writeJSON(res, 200, { items: [{ id: "email:a@b.com" }] });
  });

  const { cfg } = testConfig(hub.url + prefix);
  const page = await queryDirectory(cfg, "users");
  assert.equal(page.items[0].id, "email:a@b.com");
});

test("queryDirectory uses the correct path per directory kind", async (t) => {
  const paths: string[] = [];
  const hub = startHub(t, (req, _body, res) => {
    paths.push(req.url ?? "");
    writeJSON(res, 200, { items: [] });
  });

  const { cfg } = testConfig(hub.url);
  await queryDirectory(cfg, "users");
  await queryDirectory(cfg, "groups");
  await queryDirectory(cfg, "policies");

  assert.deepEqual(paths, ["/v1/users", "/v1/groups", "/v1/policies"]);
});

test("queryDirectory rejects a non-200 response", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 401, { error: "unknown_sender" });
  });
  const { cfg } = testConfig(hub.url);
  await assert.rejects(queryDirectory(cfg, "policies"), ProtocolError);
});

test("nested labeled entries build via entry/group helpers stay valid on the wire", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg } = testConfig(hub.url);
  const req = testRequest();
  req.action.details = [
    entry("amount", "Amount", "$500"),
    group("target", "Target", entry("account", "Account", "acct_1")),
  ];
  await assert.doesNotReject(sendRequest(cfg, req));
});

test("queryDirectory aborts on the caller's signal", async (t) => {
  const hub = startHub(t, () => {
    // Never responds: only the caller's signal can end this.
  });

  const { cfg } = testConfig(hub.url);
  const ctrl = new AbortController();
  const pending = queryDirectory(cfg, "users", { signal: ctrl.signal });
  ctrl.abort();
  await assert.rejects(pending);
});

// sendRequest sleeps between attempts; an abort during that sleep must not
// cost the remaining backoff or a second attempt.
test("sendRequest aborts promptly with the abort reason instead of retrying", async (t) => {
  let calls = 0;
  const ctrl = new AbortController();
  const reason = new Error("caller gave up");
  const hub = startHub(t, (_req, _body, res) => {
    calls++;
    res.writeHead(503);
    res.end();
    ctrl.abort(reason); // fires while sendRequest is sleeping before attempt 2
  });

  const { cfg } = testConfig(hub.url);
  const start = Date.now();
  await assert.rejects(sendRequest(cfg, testRequest(), ctrl.signal), (err: unknown) => err === reason);

  assert.equal(calls, 1); // the abort preempted the sleep, so no second attempt was made
  assert.ok(Date.now() - start < 2000); // well under the 4s second backoff
});

test("queryDirectory rejects a response body over the size limit", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"items":[{"id":"' + "a".repeat(1 << 20) + '"}]}');
  });

  const { cfg } = testConfig(hub.url);
  await assert.rejects(queryDirectory(cfg, "users"), ProtocolError);
});

// --- sendRequest: the fields it owns on the wire ---

test("sendRequest fills senderId, recipientId, requestId, callbackUrl, and expiresAt correctly on the wire", async (t) => {
  const hub = startHub(t, (_req, _body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });

  const { cfg } = testConfig(hub.url);
  cfg.sp.callbackUrl = "https://sp.example.com/hooks/stepauth";
  const before = Date.now();
  await sendRequest(cfg, testRequest());

  const envelope = JSON.parse(hub.bodies[0].toString()) as { payload: string };
  const wire = JSON.parse(Buffer.from(envelope.payload, "base64").toString()) as {
    senderId: string;
    recipientId: string;
    requestId: string;
    callbackUrl?: string;
    timestamp: string;
    expiresAt: string;
  };

  assert.equal(wire.senderId, "sp.example.com");
  assert.equal(wire.recipientId, "hub.example.com");
  assert.match(wire.requestId, /^req_[0-9a-f]{32}$/);
  assert.equal(wire.callbackUrl, "https://sp.example.com/hooks/stepauth");
  assert.ok(Date.parse(wire.timestamp) >= before - 1000); // rfc3339() truncates sub-second precision
  assert.equal(Date.parse(wire.expiresAt) - Date.parse(wire.timestamp), 30 * 60 * 1000);
});

test("sendRequest rejects an invalid request without ever calling fetch", async () => {
  let fetchCalls = 0;
  const cfg: Config = {
    signingKeyset: generateKeyset("ks_sp"),
    sp: { entity: "sp.example.com" },
    hubs: [
      {
        tag: "primary",
        default: true,
        metadata: { entity: "hub.example.com", keysets: [publicKeyset(generateKeyset("ks_hub"))], host: "http://127.0.0.1:1" },
      },
    ],
    fetch: (() => {
      fetchCalls++;
      throw new Error("fetch should never be called");
    }),
  };

  const req = testRequest();
  // @ts-expect-error deliberately outside the closed registry
  req.action.category = "unknown.category";
  await assert.rejects(sendRequest(cfg, req), ProtocolError);
  assert.equal(fetchCalls, 0);
});
