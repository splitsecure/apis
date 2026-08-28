import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash } from "node:crypto";

import {
  generateKeyset,
  publicKeyset,
  signEnvelope,
  sendRequest,
  createCallbackHandler,
  type Config,
  type HubEntry,
  type PendingState,
  type Decision,
  type ExecutionResult,
} from "../src/stepauth/index.js";

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

/** Registers its own cleanup on t, so a test that throws before its trailing
 * close() still shuts the server down instead of hanging the runner. */
function startHub(
  t: TestContext,
  handle: (body: Buffer, res: ServerResponse) => void,
): {
  url: string;
  bodies: Buffer[];
} {
  const bodies: Buffer[] = [];
  const server = createServer((req, res) => {
    void readBody(req).then((body) => {
      bodies.push(body);
      handle(body, res);
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

function testConfig(hubURL: string): { cfg: Config; hub: HubEntry; hubKeyset: ReturnType<typeof generateKeyset> } {
  const spKeyset = generateKeyset("ks_sp");
  const hubKeyset = generateKeyset("ks_hub");
  const hub: HubEntry = {
    tag: "primary",
    default: true,
    metadata: { entity: "hub.example.com", keysets: [publicKeyset(hubKeyset)], host: hubURL },
  };
  const cfg: Config = {
    signingKeyset: spKeyset,
    sp: { entity: "sp.example.com" },
    hubs: [hub],
  };
  return { cfg, hub, hubKeyset };
}

async function pendingStateFor(cfg: Config, hub: { bodies: Buffer[] }, requestId: string): Promise<PendingState> {
  const { state } = await sendRequest(cfg, {
    requestId,
    principal: { subject: "email:a@b.com" },
    action: { type: "acme.widget.delete", category: "data.delete", summary: "Delete widget" },
  });
  return state;
}

function decisionEnvelopeFor(
  hubKeyset: ReturnType<typeof generateKeyset>,
  hub: { bodies: Buffer[] },
  decisionOverrides: Partial<Decision> = {},
): string {
  const requestPayload = Buffer.from(
    (JSON.parse(hub.bodies[hub.bodies.length - 1].toString()) as { payload: string }).payload,
    "base64",
  );
  const digest = createHash("sha256").update(requestPayload).digest("base64");
  const decision: Decision = {
    requestId: "req_x",
    senderId: "hub.example.com",
    recipientId: "sp.example.com",
    decision: "approved",
    decidedAt: new Date().toISOString(),
    decidedBy: ["email:approver@b.com"],
    requestDigest: { algorithm: "sha256", value: digest },
    ...decisionOverrides,
  };
  return signEnvelope(hubKeyset, new TextEncoder().encode(JSON.stringify(decision)));
}

test("an unknown requestId is rejected before verification even runs", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg } = testConfig(hub.url);
  await pendingStateFor(cfg, hub, "req_x");

  let verifyAttempted = false;
  const handler = createCallbackHandler(
    cfg,
    () => {
      // Lookup returns nothing: this simulates a requestId this SP never
      // generated, so nothing below should ever ask "is this signature valid?".
      return null;
    },
    (): ExecutionResult => {
      verifyAttempted = true;
      return { requestId: "req_x", status: "success" };
    },
  );

  // An envelope with garbage signature bytes: if verification ran before the
  // lookup rejected it, it would throw from inside verifyEnvelope instead of
  // cleanly reaching the lookup-miss path.
  const bogus = signEnvelope(generateKeyset("ks_unrelated"), new TextEncoder().encode(`{"requestId":"req_unknown"}`));
  const resp = await handler(bogus);

  assert.equal(resp.status, 401); // same status a bad-signature rejection would give
  assert.equal(verifyAttempted, false);
});

test("a fully verified decision reaches the handler and its result is returned", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const state = await pendingStateFor(cfg, hub, "req_x");

  const handler = createCallbackHandler(
    cfg,
    (requestId) => (requestId === state.requestId ? state : null),
    (decision): ExecutionResult => ({ requestId: decision.requestId, status: "success" }),
  );

  const envelope = decisionEnvelopeFor(hubKeyset, hub);
  const resp = await handler(envelope);

  assert.equal(resp.status, 200);
  assert.deepEqual(resp.body, { requestId: "req_x", status: "success" });
});

test("a redelivery replays the recorded result instead of running the handler again", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const state = await pendingStateFor(cfg, hub, "req_x");
  const recorded: ExecutionResult = { requestId: "req_x", status: "success" };

  let calls = 0;
  const handler = createCallbackHandler(
    cfg,
    (requestId) => (requestId === state.requestId ? { ...state, result: recorded } : null),
    (): ExecutionResult => {
      calls++;
      return recorded;
    },
  );

  const envelope = decisionEnvelopeFor(hubKeyset, hub);
  const first = await handler(envelope);
  const second = await handler(envelope);

  assert.equal(calls, 0);
  assert.equal(first.status, 200);
  assert.deepEqual(first.body, recorded);
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, recorded);
});

test("a decision that fails verification is rejected with no distinguishing detail", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const state = await pendingStateFor(cfg, hub, "req_x");

  const handler = createCallbackHandler(
    cfg,
    (requestId) => (requestId === state.requestId ? state : null),
    (): ExecutionResult => ({ requestId: "req_x", status: "success" }),
  );

  // Wrong recipientId: verifies but fails check 3.
  const envelope = decisionEnvelopeFor(hubKeyset, hub, { recipientId: "someone-else.example.com" });
  const resp = await handler(envelope);

  assert.equal(resp.status, 401);
  assert.equal(resp.body.status, "error");
});

test("a handler that throws returns a 200 with an error ExecutionResult, not a rejection", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const state = await pendingStateFor(cfg, hub, "req_x");

  const handler = createCallbackHandler(
    cfg,
    (requestId) => (requestId === state.requestId ? state : null),
    (): ExecutionResult => {
      throw new Error("downstream execution failed");
    },
  );

  const envelope = decisionEnvelopeFor(hubKeyset, hub);
  const resp = await handler(envelope);

  // A handler throw reaches here only after all four verification checks
  // passed, so it's the protocol's own "verified, but execution failed" case,
  // not a rejection the hub should redeliver for 24h.
  assert.equal(resp.status, 200);
  assert.deepEqual(resp.body, { requestId: "req_x", status: "error", error: "downstream execution failed" });
});

test("a malformed body (not a valid envelope) is rejected without throwing", async () => {
  const { cfg } = testConfig("http://unused");
  const handler = createCallbackHandler(cfg, () => null, (): ExecutionResult => ({ requestId: "x", status: "success" }));

  const resp = await handler("not json at all");
  assert.equal(resp.status, 401);
});

// A lookup backed by a database can reject (a dropped connection, a timeout);
// that must reach the caller as the normal 401 rejection, not an exception
// out of this public, unauthenticated route.
test("a lookup that rejects returns the normal 401 rejection rather than throwing", async () => {
  const { cfg } = testConfig("http://unused");
  const handler = createCallbackHandler(
    cfg,
    () => Promise.reject(new Error("db connection dropped")),
    (): ExecutionResult => ({ requestId: "x", status: "success" }),
  );

  const bogus = signEnvelope(generateKeyset("ks_unrelated"), new TextEncoder().encode(`{"requestId":"req_x"}`));
  const resp = await handler(bogus);

  assert.equal(resp.status, 401);
  assert.deepEqual(resp.body, { requestId: "", status: "error" });
});

test("a body over the size limit is rejected before any parsing", async () => {
  const { cfg } = testConfig("http://unused");
  const handler = createCallbackHandler(cfg, () => null, (): ExecutionResult => ({ requestId: "x", status: "success" }));

  const resp = await handler("a".repeat((1 << 20) + 1));
  assert.equal(resp.status, 401);
});

test("createCallbackHandler accepts raw bytes as well as a string body", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const state = await pendingStateFor(cfg, hub, "req_x");

  const handler = createCallbackHandler(
    cfg,
    (requestId) => (requestId === state.requestId ? state : null),
    (decision): ExecutionResult => ({ requestId: decision.requestId, status: "success" }),
  );

  const envelope = decisionEnvelopeFor(hubKeyset, hub);
  const resp = await handler(new TextEncoder().encode(envelope));

  assert.equal(resp.status, 200);
});

test("every rejection cause returns the identical response shape", async (t) => {
  const hub = startHub(t, (_body, res) => {
    writeJSON(res, 202, { requestId: "req_x", status: "pending", createdAt: new Date().toISOString() });
  });
  const { cfg, hubKeyset } = testConfig(hub.url);
  const state = await pendingStateFor(cfg, hub, "req_x");
  const lookup = (requestId: string) => (requestId === state.requestId ? state : null);

  const malformedBody = await createCallbackHandler(cfg, lookup, (): ExecutionResult => ({
    requestId: "req_x",
    status: "success",
  }))("not an envelope");

  const bogusSig = signEnvelope(generateKeyset("ks_unrelated"), new TextEncoder().encode(`{"requestId":"req_x"}`));
  const badSignature = await createCallbackHandler(cfg, lookup, (): ExecutionResult => ({
    requestId: "req_x",
    status: "success",
  }))(bogusSig);

  const unknownRequestId = await createCallbackHandler(cfg, () => null, (): ExecutionResult => ({
    requestId: "req_x",
    status: "success",
  }))(decisionEnvelopeFor(hubKeyset, hub));

  for (const resp of [malformedBody, badSignature, unknownRequestId]) {
    assert.equal(resp.status, 401);
    assert.deepEqual(resp.body, { requestId: "", status: "error" });
  }
});
