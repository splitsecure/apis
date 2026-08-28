package stepauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testConfig returns a Config wired to hub, plus the SP's own SigningKeyset
// (so a fake-hub test server can verify what the client signed).
func testConfig(t *testing.T, hub HubEntry) (*Config, *SigningKeyset) {
	t.Helper()
	spKS, err := GenerateKeyset("sp-ks")
	if err != nil {
		t.Fatalf("generating SP keyset: %v", err)
	}
	cfg := &Config{
		SPEntity:      "sp.example.com",
		SigningKeyset: spKS,
		Hubs:          []HubEntry{hub},
	}
	return cfg, spKS
}

// testHub returns a HubEntry pointed at host, plus the hub's own SigningKeyset
// (so a test can sign fake decisions/responses as that hub).
func testHub(t *testing.T, host string) (HubEntry, *SigningKeyset) {
	t.Helper()
	hubKS, err := GenerateKeyset("hub-ks")
	if err != nil {
		t.Fatalf("generating hub keyset: %v", err)
	}
	return HubEntry{
		Tag:     "prod",
		Entity:  "hub.example.com",
		Host:    host,
		Keysets: []Keyset{hubKS.PublicKeyset()},
		Default: true,
	}, hubKS
}

func testRequest() *AuthorizationRequest {
	return &AuthorizationRequest{
		Principal: Principal{Subject: Email("a@b.com")},
		Action: Action{
			Type:     "sp.example.deploy",
			Category: CategoryCodeDeploy,
			Summary:  "Deploy the payments service",
		},
	}
}

// TestSendRequest_FreezesBytesAcrossRetries proves the freeze rule: a retried
// submission re-sends the exact bytes signed on attempt 1, never a re-signed
// envelope. Deleting the freeze (rebuilding/re-signing per attempt) makes
// this fail, since two signatures over the same payload still differ.
func TestSendRequest_FreezesBytesAcrossRetries(t *testing.T) {
	var bodies [][]byte
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(PendingResponse{RequestID: "req_1", Status: "pending", CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	}))
	defer srv.Close()

	hub, _ := testHub(t, srv.URL)
	cfg, _ := testConfig(t, hub)

	result, state, err := SendRequest(context.Background(), cfg, "", testRequest())
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if result.AlreadySubmitted {
		t.Errorf("AlreadySubmitted = true, want false")
	}
	if state == nil {
		t.Fatal("PendingState is nil")
	}
	if len(bodies) != 2 {
		t.Fatalf("got %d attempts, want 2", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Errorf("retry sent different bytes than attempt 1:\nattempt1=%s\nattempt2=%s", bodies[0], bodies[1])
	}
}

// TestSendRequest_DuplicateOnFirstAttemptErrors: a 409 on the very first
// attempt means this client never transmitted anything before, so the id
// belongs to someone else's request — a real error, not success.
func TestSendRequest_DuplicateOnFirstAttemptErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(CodeDuplicateRequest)})
	}))
	defer srv.Close()

	hub, _ := testHub(t, srv.URL)
	cfg, _ := testConfig(t, hub)

	result, state, err := SendRequest(context.Background(), cfg, "", testRequest())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %+v", result)
	}
	// state must still come back: the hub may have received these bytes, and
	// the caller needs it to verify an eventual decision against.
	if state == nil {
		t.Error("expected a non-nil PendingState on error, got nil")
	}
	var pe *ProtocolError
	ok := errors.As(err, &pe)
	if !ok || pe.Code != CodeDuplicateRequest {
		t.Errorf("err = %v, want a ProtocolError with code duplicate_request", err)
	}
}

// oneConnFailTransport fails the first RoundTrip with a connect-time network
// error (never reaching srv) and delegates every later call.
type oneConnFailTransport struct {
	failed bool
}

func (t *oneConnFailTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.failed {
		t.failed = true
		return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	}
	return http.DefaultTransport.RoundTrip(req)
}

// TestSendRequest_DuplicateAfterConnectFailureErrors: attempt 1 fails before
// any bytes reach the hub (a connect error, not a lost response), so attempt
// 2 is this client's first ever transmission. A duplicate_request there is a
// genuine collision, not proof of our own retry landing.
func TestSendRequest_DuplicateAfterConnectFailureErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(CodeDuplicateRequest)})
	}))
	defer srv.Close()

	hub, _ := testHub(t, srv.URL)
	cfg, _ := testConfig(t, hub)
	cfg.HTTPClient = &http.Client{Transport: &oneConnFailTransport{}}

	result, state, err := SendRequest(context.Background(), cfg, "", testRequest())
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %+v", result)
	}
	if state == nil {
		t.Error("expected a non-nil PendingState on error, got nil")
	}
}

// TestSendRequest_DuplicateAfterDroppedResponseSucceeds: attempt 1's response
// never reaches the client (a 503 stands in for a dropped/retried response),
// attempt 2 replays the frozen bytes and the hub reports duplicate_request —
// proof this client's own attempt 1 already landed. That must surface as
// success with AlreadySubmitted, not an error.
func TestSendRequest_DuplicateAfterDroppedResponseSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": string(CodeDuplicateRequest)})
	}))
	defer srv.Close()

	hub, _ := testHub(t, srv.URL)
	cfg, _ := testConfig(t, hub)

	result, state, err := SendRequest(context.Background(), cfg, "", testRequest())
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if !result.AlreadySubmitted {
		t.Errorf("AlreadySubmitted = false, want true")
	}
	if result.CreatedAt != "" {
		t.Errorf("CreatedAt = %q, want empty: the hub does not repeat it", result.CreatedAt)
	}
	if state == nil {
		t.Fatal("PendingState is nil")
	}
}

// signedDecision builds and signs a Decision envelope with hubKS.
func signedDecision(t *testing.T, hubKS *SigningKeyset, d Decision) []byte {
	t.Helper()
	payload, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshaling decision: %v", err)
	}
	env, err := SignEnvelope(hubKS, payload)
	if err != nil {
		t.Fatalf("signing decision: %v", err)
	}
	return env
}

func validDecisionFor(state *PendingState, spEntity string) Decision {
	return Decision{
		RequestID:     state.RequestID,
		SenderID:      state.HubEntity,
		RecipientID:   spEntity,
		Decision:      DecisionApproved,
		DecidedAt:     time.Now().UTC().Format(time.RFC3339),
		DecidedBy:     []string{"email:approver@example.com"},
		RequestDigest: Digest{Algorithm: DigestSHA256, Value: sha256Base64(state.Payload)},
	}
}

func TestVerifyDecision_Valid(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	env := signedDecision(t, hubKS, validDecisionFor(state, cfg.SPEntity))
	d, err := VerifyDecision(cfg, env, state)
	if err != nil {
		t.Fatalf("VerifyDecision: %v", err)
	}
	if d.RequestID != "req_1" {
		t.Errorf("RequestID = %q, want req_1", d.RequestID)
	}
}

// TestVerifyDecision_SignatureInvalid signs an otherwise-valid decision with
// a keyset the hub metadata never registered, so only the signature check
// can reject it: senderId, recipientId, and the digest all still match.
func TestVerifyDecision_SignatureInvalid(t *testing.T) {
	hub, _ := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	foreignKS, err := GenerateKeyset("foreign-ks")
	if err != nil {
		t.Fatalf("generating foreign keyset: %v", err)
	}
	env := signedDecision(t, foreignKS, validDecisionFor(state, cfg.SPEntity))

	if _, err := VerifyDecision(cfg, env, state); err == nil {
		t.Fatal("expected an error for a decision signed by an unregistered keyset, got nil")
	}
}

// TestVerifyDecision_SenderMismatch: the envelope verifies (still the
// registered hub keyset), but senderId doesn't match the hub this request
// went to — a substituted-hub attack, not a signature failure.
func TestVerifyDecision_SenderMismatch(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	d := validDecisionFor(state, cfg.SPEntity)
	d.SenderID = "attacker-hub.example.com"
	env := signedDecision(t, hubKS, d)

	_, err := VerifyDecision(cfg, env, state)
	if !errors.Is(err, ErrDecisionSenderMismatch) {
		t.Errorf("err = %v, want ErrDecisionSenderMismatch", err)
	}
}

// TestVerifyDecision_RecipientMismatch: a decision correctly signed by the
// right hub but addressed to a different SP — a decision replayed to the
// wrong recipient.
func TestVerifyDecision_RecipientMismatch(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	d := validDecisionFor(state, cfg.SPEntity)
	d.RecipientID = "other-sp.example.com"
	env := signedDecision(t, hubKS, d)

	_, err := VerifyDecision(cfg, env, state)
	if !errors.Is(err, ErrDecisionRecipientMismatch) {
		t.Errorf("err = %v, want ErrDecisionRecipientMismatch", err)
	}
}

// TestVerifyDecision_DigestMismatch: a decision correctly signed and
// addressed, but bound to a different request payload than the one stored.
func TestVerifyDecision_DigestMismatch(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	d := validDecisionFor(state, cfg.SPEntity)
	d.RequestDigest = Digest{Algorithm: DigestSHA256, Value: sha256Base64([]byte(`{"requestId":"some-other-request"}`))}
	env := signedDecision(t, hubKS, d)

	_, err := VerifyDecision(cfg, env, state)
	if !errors.Is(err, ErrDecisionDigestMismatch) {
		t.Errorf("err = %v, want ErrDecisionDigestMismatch", err)
	}
}

// TestListUsers_SignedBodyAndRequestURI checks the directory call sends a
// signed query, binds requestUri to the exact path requested, and follows
// nextCursor to page through results.
func TestListUsers_SignedBodyAndRequestURI(t *testing.T) {
	var queries []DirectoryQuery
	var seenPaths []string

	var spPub []Keyset
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.URL.RequestURI())

		envBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		payload, err := VerifyEnvelope(envBytes, spPub)
		if err != nil {
			t.Errorf("directory query did not verify against the SP's keyset: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var q DirectoryQuery
		if err := json.Unmarshal(payload, &q); err != nil {
			t.Errorf("unmarshaling query: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		queries = append(queries, q)

		if q.RequestURI != r.URL.RequestURI() {
			t.Errorf("requestUri = %q, want %q", q.RequestURI, r.URL.RequestURI())
		}

		w.WriteHeader(http.StatusOK)
		if q.Cursor == "" {
			_ = json.NewEncoder(w).Encode(DirectoryPage{
				Items:      []DirectoryItem{{ID: "email:a@b.com"}},
				NextCursor: "cursor-1",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(DirectoryPage{Items: []DirectoryItem{{ID: "email:c@d.com"}}})
	}))
	defer srv.Close()

	hub, _ := testHub(t, srv.URL)
	cfg, spKS := testConfig(t, hub)
	spPub = []Keyset{spKS.PublicKeyset()}

	page1, err := ListUsers(context.Background(), cfg, "", DirectoryOpts{Limit: 1})
	if err != nil {
		t.Fatalf("ListUsers page 1: %v", err)
	}
	if page1.NextCursor != "cursor-1" {
		t.Fatalf("page1.NextCursor = %q, want cursor-1", page1.NextCursor)
	}

	page2, err := ListUsers(context.Background(), cfg, "", DirectoryOpts{Limit: 1, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatalf("ListUsers page 2: %v", err)
	}
	if len(page2.Items) != 1 || page2.Items[0].ID != "email:c@d.com" {
		t.Errorf("page2.Items = %+v, want one item email:c@d.com", page2.Items)
	}

	for _, p := range seenPaths {
		if !strings.HasSuffix(p, "/v1/users") {
			t.Errorf("request path %q does not target /v1/users", p)
		}
	}
	if len(queries) != 2 || queries[1].Cursor != "cursor-1" {
		t.Errorf("second query cursor = %q, want cursor-1", queries[1].Cursor)
	}
}

// TestDirectory_PrefixedHubHost checks the signed requestUri carries the hub's
// path prefix. The hub serves every org under a /stepauth/{orgID} path prefix
// and compares requestUri against its own r.URL.RequestURI(), so a bare
// "/v1/users" reads to the hub as a replay against a different resource.
func TestDirectory_PrefixedHubHost(t *testing.T) {
	const prefix = "/stepauth/org_123"

	var spPub []Keyset
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+prefix+"/v1/users", func(w http.ResponseWriter, r *http.Request) {
		envBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		payload, err := VerifyEnvelope(envBytes, spPub)
		if err != nil {
			t.Errorf("directory query did not verify: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var q DirectoryQuery
		if err := json.Unmarshal(payload, &q); err != nil {
			t.Errorf("unmarshaling query: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Rejected the way the hub rejects it, rather than trusting whatever
		// the client happened to sign.
		if q.RequestURI != r.URL.RequestURI() {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]Code{"error": CodeWrongRecipient})
			return
		}
		_ = json.NewEncoder(w).Encode(DirectoryPage{Items: []DirectoryItem{{ID: "email:a@b.com"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hub, _ := testHub(t, srv.URL+prefix)
	cfg, spKS := testConfig(t, hub)
	spPub = []Keyset{spKS.PublicKeyset()}

	page, err := ListUsers(context.Background(), cfg, "", DirectoryOpts{})
	if err != nil {
		t.Fatalf("ListUsers against a prefixed hub: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "email:a@b.com" {
		t.Errorf("page.Items = %+v, want one item email:a@b.com", page.Items)
	}
}

// TestSendRequest_RejectsPresetIdentity checks a caller cannot address a
// request as another SP, or to a hub other than the one it is being sent to.
// Both are rejected before signing; the hub would otherwise see only an
// unresolvable sender or a misaddressed request.
func TestSendRequest_RejectsPresetIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the hub; it should have been rejected before signing")
	}))
	defer srv.Close()

	hub, _ := testHub(t, srv.URL)
	cfg, _ := testConfig(t, hub)

	base := func() *AuthorizationRequest {
		return &AuthorizationRequest{
			Principal: Principal{Subject: "email:op@example.com"},
			Action:    Action{Type: "com.example.act", Category: CategoryDataDelete, Summary: "s"},
		}
	}

	req := base()
	req.SenderID = "other-sp.example.com"
	if _, _, err := SendRequest(context.Background(), cfg, "", req); err == nil {
		t.Error("SendRequest accepted a request claiming another SP as sender")
	}

	req = base()
	req.RecipientID = "other-hub.example.com"
	if _, _, err := SendRequest(context.Background(), cfg, "", req); err == nil {
		t.Error("SendRequest accepted a request addressed to a different hub")
	}
}
