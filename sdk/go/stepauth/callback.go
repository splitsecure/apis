package stepauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// maxCallbackBodyBytes bounds a decision-delivery POST: only one small signed
// envelope is ever expected.
const maxCallbackBodyBytes = 1 << 20

// PendingState is what an SP must persist for a submitted request until its
// decision arrives (or it expires): the exact frozen request payload — to
// check the eventual decision's requestDigest — and which hub it was sent to,
// recorded at send time. JSON-serializable; the SDK persists nothing itself.
type PendingState struct {
	RequestID string `json:"requestId"`
	Hub       string `json:"hub"`
	HubEntity string `json:"hubEntity"`
	Payload   []byte `json:"payload"`

	// Result is the ExecutionResult already recorded for this request, if
	// the SP has executed it. Delivery is at-least-once, so a redelivery
	// must replay this rather than run the handler again.
	Result *ExecutionResult `json:"result,omitempty"`
}

// PendingLookup resolves a requestId to its stored PendingState: return the
// stored state for any requestId this SP issued, with Result set once the
// decision has been executed. Return (nil, nil) only for an id the SP never
// issued — never for an already-decided one, since nil reads to the hub as
// a rejection and it will retry delivery for 24h.
type PendingLookup func(ctx context.Context, requestID string) (*PendingState, error)

// DecisionHandler runs a verified decision (executing the approved action, or
// recording a denial) and reports back its execution. Two deliveries of one
// decision that arrive at once can both pass the recorded-result check before
// either records a result, so the handler must be idempotent by requestId.
type DecisionHandler func(ctx context.Context, decision *Decision) ExecutionResult

// NewCallbackHandler returns the SP's decision-delivery webhook: the hub
// POSTs a signed decision here directly, there is no polling. This endpoint
// carries NO transport auth of its own — the envelope signature IS the
// entire security, verified per VerifyDecision before handler ever runs.
func NewCallbackHandler(cfg *Config, lookup PendingLookup, handler DecisionHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxCallbackBodyBytes))
		if err != nil {
			reject(w)
			return
		}

		// Decoded WITHOUT verifying, only to read requestId for routing; the
		// body stays untrusted until VerifyDecision runs below.
		payload, err := DecodeEnvelopePayload(body)
		if err != nil {
			reject(w)
			return
		}
		var probe struct {
			RequestID string `json:"requestId"`
		}
		if err := json.Unmarshal(payload, &probe); err != nil || probe.RequestID == "" {
			reject(w)
			return
		}

		// An unknown requestId is rejected before any verification is
		// attempted: never authenticate a decision the SP never asked for.
		pending, err := lookup(r.Context(), probe.RequestID)
		if err != nil || pending == nil {
			reject(w)
			return
		}

		decision, err := VerifyDecision(cfg, body, pending)
		if err != nil {
			reject(w)
			return
		}

		// A redelivery of an already-decided request must replay the
		// recorded result rather than run the handler again.
		if pending.Result != nil {
			respondJSON(w, *pending.Result)
			return
		}

		respondJSON(w, handler(r.Context(), decision))
	})
}

// respondJSON writes result as the 200 response body, or a rejection if it
// cannot be marshaled.
func respondJSON(w http.ResponseWriter, result ExecutionResult) {
	b, err := json.Marshal(result)
	if err != nil {
		reject(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// reject answers every rejection identically, regardless of cause.
func reject(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
}
