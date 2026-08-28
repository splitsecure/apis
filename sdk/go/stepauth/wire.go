package stepauth

import (
	"encoding/json"
	"time"
)

// Protocol limits and constants.
const (
	// DecisionApproved and DecisionDenied are the two values of Decision.Decision.
	DecisionApproved = "approved"
	DecisionDenied   = "denied"

	// DigestSHA256 is the only digest algorithm value.
	DigestSHA256 = "sha256"

	// MaxActionNameLen bounds action.name in runes, not bytes.
	MaxActionNameLen = 120

	// MaxKeyIDLen bounds requestId and senderId.
	MaxKeyIDLen = 256

	// MaxOperatorDepth bounds principal.operator chain depth.
	MaxOperatorDepth = 5

	// MaxClockSkew bounds the difference between a request's timestamp and the
	// hub's clock.
	MaxClockSkew = 5 * time.Minute
)

// LabeledEntry is a display entry in principal.attributes and action.details.
// Value is a string or a nested []LabeledEntry, kept raw; build one with Entry
// or Group and read it back with StringValue or Children.
type LabeledEntry struct {
	Key   string          `json:"key"`
	Label string          `json:"label"`
	Value json.RawMessage `json:"value"`
}

// Target is the resource an action acts upon. Not a NameID.
type Target struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// Principal is the request initiator plus an optional informational operator chain.
type Principal struct {
	Subject    string         `json:"subject"`
	Attributes []LabeledEntry `json:"attributes,omitempty"`
	Operator   *Principal     `json:"operator,omitempty"`
}

// Action describes the operation under review.
type Action struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	// Name is the short imperative title reviewers see. Optional: a request
	// that sends none is titled by Type, then Summary.
	Name     string         `json:"name,omitempty"`
	Summary  string         `json:"summary"`
	Details  []LabeledEntry `json:"details,omitempty"`
	Target   *Target        `json:"target,omitempty"`
	Approver string         `json:"approver,omitempty"`
}

// AuthorizationRequest is the decoded payload of a submission envelope.
type AuthorizationRequest struct {
	RequestID string `json:"requestId"`
	// SenderID is the SP entity the hub resolves the registration and verifying keysets by.
	SenderID string `json:"senderId"`
	// RecipientID is the target hub tenant; a request not addressed to this tenant is rejected.
	RecipientID   string    `json:"recipientId"`
	Timestamp     string    `json:"timestamp"`
	ExpiresAt     string    `json:"expiresAt"`
	CallbackURL   string    `json:"callbackUrl,omitempty"`
	Principal     Principal `json:"principal"`
	Action        Action    `json:"action"`
	PolicyVersion string    `json:"policyVersion,omitempty"`
}

// Digest is the request-payload hash carried in a Decision.
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Decision is the decoded payload of a decision envelope.
type Decision struct {
	RequestID string `json:"requestId"`
	// SenderID is the deciding hub's entity.
	SenderID string `json:"senderId"`
	// RecipientID is the SP's entity.
	RecipientID   string   `json:"recipientId"`
	Decision      string   `json:"decision"`
	DecidedAt     string   `json:"decidedAt"`
	DecidedBy     []string `json:"decidedBy"`
	RequestDigest Digest   `json:"requestDigest"`
}

// PendingResponse is the 202 body returned by submit.
type PendingResponse struct {
	RequestID         string `json:"requestId"`
	Status            string `json:"status"`
	CreatedAt         string `json:"createdAt"`
	ReviewDescription string `json:"reviewDescription,omitempty"`
}

// ExecutionResult is the SP's acknowledgement of a delivered decision.
type ExecutionResult struct {
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}
