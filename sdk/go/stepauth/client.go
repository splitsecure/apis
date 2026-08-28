package stepauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client-side tunables.
const (
	// DefaultExpiresIn is the request validity window used when a caller
	// leaves ExpiresAt unset.
	DefaultExpiresIn = 30 * time.Minute

	defaultHTTPTimeout   = 30 * time.Second
	maxResponseBytes     = 1 << 20
	requestIDRandomBytes = 16

	// maxSendAttempts and the backoff schedule below keep SendRequest's
	// total retry budget well under 30s.
	maxSendAttempts = 3
	baseBackoff     = 250 * time.Millisecond
)

// HubEntry maps a local tag to one hub's metadata: its entity, its verifying
// keysets, and the transport origin the SDK POSTs to. host is never derived
// from entity — it may sit behind a path-prefixing proxy.
type HubEntry struct {
	Tag     string
	Entity  string
	Host    string
	Keysets []Keyset
	// Default marks the hub SendRequest, VerifyDecision's PendingLookup, and
	// the directory calls use when no tag is given. Exactly one hub must set it.
	Default bool
}

// Config holds an SP's StepAuth client identity and the hubs it talks to.
type Config struct {
	// SPEntity is this SP's own metadata entity, sent as senderId.
	SPEntity string
	// SigningKeyset signs every outgoing envelope.
	SigningKeyset *SigningKeyset
	// CallbackURL is the default callbackUrl used when a request supplies none.
	CallbackURL string
	// Hubs is the table of hubs this SP can submit to.
	Hubs []HubEntry
	// HTTPClient is the transport used for every call; nil uses a client with
	// DefaultHTTPTimeout.
	HTTPClient *http.Client
}

// ValidateConfig checks the invariants SendRequest, VerifyDecision, and the
// directory calls all depend on.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("stepauth: config is nil")
	}
	if err := cfg.SigningKeyset.validate(); err != nil {
		return err
	}
	if cfg.SPEntity == "" {
		return errors.New("stepauth: SPEntity is required")
	}
	if len(cfg.Hubs) == 0 {
		return errors.New("stepauth: at least one hub is required")
	}
	defaults := 0
	tags := make(map[string]bool, len(cfg.Hubs))
	for i, h := range cfg.Hubs {
		if h.Tag == "" {
			return fmt.Errorf("stepauth: hub at index %d has no tag", i)
		}
		if tags[h.Tag] {
			return fmt.Errorf("stepauth: duplicate hub tag %q", h.Tag)
		}
		tags[h.Tag] = true
		if h.Host == "" {
			return fmt.Errorf("stepauth: hub %q has no host", h.Tag)
		}
		if u, err := url.Parse(h.Host); err != nil || !httpsOrLoopback(u) {
			return fmt.Errorf("stepauth: hub %q host must be https, or http to localhost/127.0.0.1", h.Tag)
		}
		if h.Entity == "" {
			return fmt.Errorf("stepauth: hub %q has no entity", h.Tag)
		}
		if len(h.Keysets) == 0 {
			return fmt.Errorf("stepauth: hub %q has no keysets", h.Tag)
		}
		for _, ks := range h.Keysets {
			if err := validateKeyset(ks); err != nil {
				return err
			}
		}
		if h.Default {
			defaults++
		}
	}
	if defaults != 1 {
		return fmt.Errorf("stepauth: exactly one hub must be default, found %d", defaults)
	}
	return nil
}

// hubByTag resolves tag to its HubEntry, or the default hub when tag is "".
func (cfg *Config) hubByTag(tag string) (*HubEntry, bool) {
	if tag == "" {
		for i := range cfg.Hubs {
			if cfg.Hubs[i].Default {
				return &cfg.Hubs[i], true
			}
		}
		return nil, false
	}
	for i := range cfg.Hubs {
		if cfg.Hubs[i].Tag == tag {
			return &cfg.Hubs[i], true
		}
	}
	return nil, false
}

func httpClientFor(cfg *Config) *http.Client {
	if cfg.HTTPClient != nil {
		return cfg.HTTPClient
	}
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		// Auth lives in the signed body, not a header, so a redirect would
		// replay the envelope to an origin this SDK never configured.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// SendResult is the outcome of SendRequest: either the hub's fresh Pending
// response, or — for a retried submission that landed on an earlier
// attempt — an AlreadySubmitted acknowledgement with no CreatedAt, since the
// hub does not repeat one.
type SendResult struct {
	RequestID         string
	Status            string
	CreatedAt         string
	ReviewDescription string
	AlreadySubmitted  bool
}

// SendRequest builds, signs, and submits req to the hub named by hubTag (""
// for the default hub), filling requestId/senderId/recipientId/timestamp/
// expiresAt/callbackUrl from cfg and the hub where req leaves them unset, then
// running Validate. The envelope is signed once; every retry re-sends those
// exact bytes unchanged, since re-signing would change the digest the caller's
// eventual VerifyDecision checks against. Retries are capped at
// maxSendAttempts, exponential backoff, and only for what IsRetryable reports
// retryable. On success the caller MUST persist the returned PendingState —
// it is what VerifyDecision and the callback handler need to verify the
// eventual decision. On error, once the envelope has been sent at least
// once, the caller may still receive a non-nil PendingState alongside the
// error; it must be persisted too, since the request may have reached the
// hub despite the error.
//
// asymmetry; splitting them across helpers hides why each one exists.
//
//nolint:gocognit // the retry branches are the freeze rule and the 409
func SendRequest(ctx context.Context, cfg *Config, hubTag string, req *AuthorizationRequest) (*SendResult, *PendingState, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, nil, err
	}
	if req == nil {
		return nil, nil, errors.New("stepauth: request is required")
	}
	hub, ok := cfg.hubByTag(hubTag)
	if !ok {
		return nil, nil, fmt.Errorf("stepauth: unknown hub %q", hubTag)
	}

	wire := *req
	if err := fillRequestDefaults(cfg, hub, &wire); err != nil {
		return nil, nil, err
	}
	if we := Validate(&wire); we != nil {
		return nil, nil, we
	}

	payload, err := json.Marshal(wire)
	if err != nil {
		return nil, nil, fmt.Errorf("stepauth: marshaling request: %w", err)
	}
	envelopeBytes, err := SignEnvelope(cfg.SigningKeyset, payload)
	if err != nil {
		return nil, nil, err
	}

	state := &PendingState{
		RequestID: wire.RequestID,
		Hub:       hub.Tag,
		HubEntity: hub.Entity,
		Payload:   payload,
	}

	target := strings.TrimRight(hub.Host, "/") + "/v1/authorization-requests"
	client := httpClientFor(cfg)

	var lastErr error
	transmitted := false
	for attempt := 1; attempt <= maxSendAttempts; attempt++ {
		status, body, err := postEnvelope(ctx, client, target, envelopeBytes)
		if err != nil {
			lastErr = err
			if attempt < maxSendAttempts && IsRetryable(err) {
				if serr := sleepOrDone(ctx, backoffDelay(attempt)); serr != nil {
					return nil, state, serr
				}
				continue
			}
			return nil, state, err
		}

		if status == http.StatusAccepted {
			var pr PendingResponse
			if err := json.Unmarshal(body, &pr); err != nil {
				return nil, state, fmt.Errorf("stepauth: parsing pending response: %w", err)
			}
			return &SendResult{
				RequestID:         wire.RequestID,
				Status:            pr.Status,
				CreatedAt:         pr.CreatedAt,
				ReviewDescription: pr.ReviewDescription,
			}, state, nil
		}

		perr := parseProtocolError(status, body)
		// duplicate_request means our own retry landed only if an earlier
		// attempt actually transmitted: a connect-time failure can burn an
		// attempt without transmitting, so the attempt count alone can't
		// tell a resent id from a genuine collision.
		if perr.Code == CodeDuplicateRequest && transmitted {
			return &SendResult{RequestID: wire.RequestID, AlreadySubmitted: true}, state, nil
		}
		transmitted = true
		lastErr = perr
		if attempt < maxSendAttempts && IsRetryable(perr) {
			if serr := sleepOrDone(ctx, backoffDelay(attempt)); serr != nil {
				return nil, state, serr
			}
			continue
		}
		return nil, state, perr
	}
	return nil, state, lastErr
}

// fillRequestDefaults fills req's SDK-side defaults in place: requestId,
// senderId, recipientId, timestamp, expiresAt, callbackUrl, wherever req
// leaves them unset. senderId and recipientId are the SDK's to set — a caller
// that presets either to something else is rejected here rather than at the
// hub, which sees only an unresolvable sender or a misaddressed request.
func fillRequestDefaults(cfg *Config, hub *HubEntry, req *AuthorizationRequest) error {
	if req.SenderID != "" && req.SenderID != cfg.SPEntity {
		return fmt.Errorf("stepauth: request senderId %q is not this SP (%q)", req.SenderID, cfg.SPEntity)
	}
	if req.RecipientID != "" && req.RecipientID != hub.Entity {
		return fmt.Errorf("stepauth: request recipientId %q is not hub %q", req.RecipientID, hub.Entity)
	}

	if req.RequestID == "" {
		req.RequestID = generateRequestID()
	}
	req.SenderID = cfg.SPEntity
	req.RecipientID = hub.Entity
	now := time.Now().UTC()
	if req.Timestamp == "" {
		req.Timestamp = now.Format(time.RFC3339)
	}
	if req.ExpiresAt == "" {
		req.ExpiresAt = now.Add(DefaultExpiresIn).Format(time.RFC3339)
	}
	if req.CallbackURL == "" {
		req.CallbackURL = cfg.CallbackURL
	}
	return nil
}

func generateRequestID() string {
	b := make([]byte, requestIDRandomBytes)
	_, _ = rand.Read(b) // crypto/rand.Read does not fail on supported platforms
	return "req_" + hex.EncodeToString(b)
}

func backoffDelay(attempt int) time.Duration {
	return baseBackoff * time.Duration(1<<uint(attempt-1))
}

func sleepOrDone(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Decision-verification failures. Each is a distinct security failure, not a
// bug: a substituted hub, a decision replayed to another SP, and a decision
// bound to a different request, respectively.
var (
	ErrUnknownHub                = errors.New("stepauth: pending state names an unknown hub")
	ErrDecisionSenderMismatch    = errors.New("stepauth: decision senderId does not match the hub this request was sent to")
	ErrDecisionRecipientMismatch = errors.New("stepauth: decision recipientId does not match this SP")
	ErrDecisionDigestMismatch    = errors.New("stepauth: decision requestDigest does not match the stored request payload")
)

// VerifyDecision verifies envelopeBytes against pending in protocol order —
// envelope signature, then senderId, then recipientId, then requestDigest —
// and returns the decoded Decision only if every check passes. Any failure is
// a rejection; the caller must not act on the decision.
func VerifyDecision(cfg *Config, envelopeBytes []byte, pending *PendingState) (*Decision, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, errors.New("stepauth: pending state is required")
	}
	hub, ok := cfg.hubByTag(pending.Hub)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownHub, pending.Hub)
	}

	// 1. Envelope signature, all-of, against the hub's keysets.
	payload, err := VerifyEnvelope(envelopeBytes, hub.Keysets)
	if err != nil {
		return nil, err
	}
	var d Decision
	if err := json.Unmarshal(payload, &d); err != nil {
		return nil, fmt.Errorf("stepauth: parsing decision payload: %w", err)
	}

	// 2. senderId must equal the hub entity recorded in PendingState at send
	// time — not looked up now, so a re-tagged config can't change what's
	// expected.
	if d.SenderID != pending.HubEntity {
		return nil, ErrDecisionSenderMismatch
	}
	// 3. recipientId must be this SP.
	if d.RecipientID != cfg.SPEntity {
		return nil, ErrDecisionRecipientMismatch
	}
	// 4. requestDigest must be sha256 over the exact stored payload bytes.
	if d.RequestDigest.Algorithm != DigestSHA256 || d.RequestDigest.Value != sha256Base64(pending.Payload) {
		return nil, ErrDecisionDigestMismatch
	}
	return &d, nil
}

func sha256Base64(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// DirectoryQuery is the signed payload authenticating a directory read. It
// binds to the exact resource path via RequestURI, so the signature can't be
// replayed against a different endpoint or org.
type DirectoryQuery struct {
	SenderID    string `json:"senderId"`
	RecipientID string `json:"recipientId"`
	RequestURI  string `json:"requestUri"`
	Timestamp   string `json:"timestamp"`
	Limit       int    `json:"limit,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
}

// DirectoryItem is one routable approver: a user, a group, or a policy.
type DirectoryItem struct {
	ID         string `json:"id"`
	Label      string `json:"label,omitempty"`
	Provenance string `json:"provenance,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Count      int    `json:"count,omitempty"`
}

// DirectoryPage is one page of a directory listing.
type DirectoryPage struct {
	Items []DirectoryItem `json:"items"`
	// NextCursor is empty when the last page was returned.
	NextCursor string `json:"nextCursor,omitempty"`
}

// DirectoryOpts are the (signed) paging parameters of a directory query.
type DirectoryOpts struct {
	Limit  int
	Cursor string
}

// ListUsers lists the org's routable member emails.
func ListUsers(ctx context.Context, cfg *Config, hubTag string, opts DirectoryOpts) (*DirectoryPage, error) {
	return queryDirectory(ctx, cfg, hubTag, "users", opts)
}

// ListGroups lists the org's routable groups.
func ListGroups(ctx context.Context, cfg *Config, hubTag string, opts DirectoryOpts) (*DirectoryPage, error) {
	return queryDirectory(ctx, cfg, hubTag, "groups", opts)
}

// ListPolicies lists the org's stored policy names.
func ListPolicies(ctx context.Context, cfg *Config, hubTag string, opts DirectoryOpts) (*DirectoryPage, error) {
	return queryDirectory(ctx, cfg, hubTag, "policies", opts)
}

func queryDirectory(ctx context.Context, cfg *Config, hubTag, resource string, opts DirectoryOpts) (*DirectoryPage, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	hub, ok := cfg.hubByTag(hubTag)
	if !ok {
		return nil, fmt.Errorf("stepauth: unknown hub %q", hubTag)
	}

	rawURL := strings.TrimRight(hub.Host, "/") + "/v1/" + resource
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("stepauth: parsing hub host: %w", err)
	}

	q := DirectoryQuery{
		SenderID:    cfg.SPEntity,
		RecipientID: hub.Entity,
		RequestURI:  u.RequestURI(),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Limit:       opts.Limit,
		Cursor:      opts.Cursor,
	}
	payload, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("stepauth: marshaling directory query: %w", err)
	}
	envelopeBytes, err := SignEnvelope(cfg.SigningKeyset, payload)
	if err != nil {
		return nil, err
	}

	status, body, err := postEnvelope(ctx, httpClientFor(cfg), rawURL, envelopeBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, parseProtocolError(status, body)
	}
	var page DirectoryPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("stepauth: parsing directory page: %w", err)
	}
	return &page, nil
}

// postEnvelope POSTs body to target and returns the response status and body.
// A transport failure is wrapped with %w so IsRetryable's net.Error branch
// still reaches the underlying error.
func postEnvelope(ctx context.Context, client *http.Client, target string, body []byte) (status int, respBody []byte, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("stepauth: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq) //nolint:gosec // target is a hub host from trusted config
	if err != nil {
		return 0, nil, fmt.Errorf("stepauth: POST %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("stepauth: reading response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// parseProtocolError builds a ProtocolError carrying the status actually
// observed on the wire, so IsRetryable's 5xx check reflects what the hub sent
// rather than a code->status table guess.
func parseProtocolError(status int, body []byte) *ProtocolError {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &e)
	code := Code(e.Error)
	if code == "" {
		code = Code(fmt.Sprintf("http_%d", status))
	}
	return &ProtocolError{HTTPStatus: status, Code: code, Message: e.Message}
}
