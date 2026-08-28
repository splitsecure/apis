package stepauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func noopDecisionHandler(_ context.Context, d *Decision) ExecutionResult {
	return ExecutionResult{RequestID: d.RequestID, Status: "executed"}
}

// TestCallbackHandler_UnknownRequestIDRejectedBeforeVerification checks that a
// validly signed, correctly addressed decision for a requestId the SP never
// issued is still rejected.
func TestCallbackHandler_UnknownRequestIDRejectedBeforeVerification(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_known", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_known"}`)}

	lookupCalled := false
	lookup := func(_ context.Context, requestID string) (*PendingState, error) {
		lookupCalled = true
		if requestID == state.RequestID {
			return state, nil
		}
		return nil, nil // unknown to this SP
	}

	// A validly signed, correctly addressed decision — but for a requestId the
	// lookup does not recognize.
	other := *state
	other.RequestID = "req_unknown"
	env := signedDecision(t, hubKS, validDecisionFor(&other, cfg.SPEntity))

	handler := NewCallbackHandler(cfg, lookup, noopDecisionHandler)
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(string(env)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !lookupCalled {
		t.Fatal("lookup was never called")
	}
	if rec.Code == http.StatusOK {
		t.Errorf("status = %d, want a rejection", rec.Code)
	}
}

func TestCallbackHandler_ValidDecisionRunsHandler(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	lookup := func(_ context.Context, requestID string) (*PendingState, error) {
		if requestID == state.RequestID {
			return state, nil
		}
		return nil, nil
	}
	env := signedDecision(t, hubKS, validDecisionFor(state, cfg.SPEntity))

	handler := NewCallbackHandler(cfg, lookup, noopDecisionHandler)
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(string(env)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var result ExecutionResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	if result.RequestID != "req_1" || result.Status != "executed" {
		t.Errorf("result = %+v, want {RequestID: req_1, Status: executed}", result)
	}
}

// TestCallbackHandler_RedeliveryReplaysRecordedResultWithoutRerunningHandler
// simulates the hub's at-least-once delivery: the same decision arrives
// twice. The second lookup reflects that the SP already executed it (Result
// set), so the handler must not run again, and the response must still carry
// the recorded result rather than a rejection.
func TestCallbackHandler_RedeliveryReplaysRecordedResultWithoutRerunningHandler(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}
	env := signedDecision(t, hubKS, validDecisionFor(state, cfg.SPEntity))

	handlerCalls := 0
	handler := func(_ context.Context, d *Decision) ExecutionResult {
		handlerCalls++
		return ExecutionResult{RequestID: d.RequestID, Status: "executed"}
	}

	var recorded *ExecutionResult
	lookup := func(_ context.Context, requestID string) (*PendingState, error) {
		if requestID != state.RequestID {
			return nil, nil
		}
		s := *state
		s.Result = recorded
		return &s, nil
	}

	h := NewCallbackHandler(cfg, lookup, handler)

	for i := range 2 {
		req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(string(env)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("delivery %d: status = %d, want 200; body=%s", i, rec.Code, rec.Body.String())
		}
		var result ExecutionResult
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatalf("delivery %d: unmarshaling response: %v", i, err)
		}
		if result.RequestID != "req_1" || result.Status != "executed" {
			t.Errorf("delivery %d: result = %+v, want {RequestID: req_1, Status: executed}", i, result)
		}
		recorded = &result
	}

	if handlerCalls != 1 {
		t.Errorf("handler ran %d times across two deliveries, want 1", handlerCalls)
	}
}

func TestCallbackHandler_InvalidDecisionRejected(t *testing.T) {
	hub, hubKS := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)
	state := &PendingState{RequestID: "req_1", Hub: hub.Tag, HubEntity: hub.Entity, Payload: []byte(`{"requestId":"req_1"}`)}

	lookup := func(_ context.Context, requestID string) (*PendingState, error) {
		if requestID == state.RequestID {
			return state, nil
		}
		return nil, nil
	}

	d := validDecisionFor(state, cfg.SPEntity)
	d.RequestDigest.Value = sha256Base64([]byte("wrong payload"))
	env := signedDecision(t, hubKS, d)

	handler := NewCallbackHandler(cfg, lookup, noopDecisionHandler)
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(string(env)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("status = %d, want a rejection", rec.Code)
	}
}

func TestCallbackHandler_MalformedBodyRejected(t *testing.T) {
	hub, _ := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)

	handler := NewCallbackHandler(cfg, func(context.Context, string) (*PendingState, error) {
		t.Fatal("lookup should not run for a malformed envelope")
		return nil, nil
	}, noopDecisionHandler)

	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("status = %d, want a rejection", rec.Code)
	}
}

func TestCallbackHandler_RejectionsCarryNoDistinguishingDetail(t *testing.T) {
	hub, _ := testHub(t, "https://hub.invalid")
	cfg, _ := testConfig(t, hub)

	handler := NewCallbackHandler(cfg, func(context.Context, string) (*PendingState, error) {
		return nil, nil
	}, noopDecisionHandler)

	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Body.Len() != 0 {
		t.Errorf("rejection body = %q, want empty", rec.Body.String())
	}
}
