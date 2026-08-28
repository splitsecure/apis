package stepauth

import (
	"fmt"
	"net/url"
	"regexp"
	"time"
	"unicode/utf8"
)

// loopbackRe matches an http loopback host (localhost/127.0.0.1), the hub's
// dev allowance for callbackUrl.
var loopbackRe = regexp.MustCompile(`^(localhost|127\.0\.0\.1)$`)

// Validate runs the pre-send checks the hub itself enforces, so a caller
// gets a local error instead of a round trip. It returns error rather than
// *ProtocolError so a caller wrapping it in an error-returning function does
// not turn a valid request into a typed-nil failure; recover the code with
// errors.As.
func Validate(req *AuthorizationRequest) error {
	if req == nil {
		return NewProtocolError(CodeMalformedRequest, "request is nil")
	}
	if err := validateFields(req); err != nil {
		return err
	}
	if err := validateTiming(req, time.Now()); err != nil {
		return err
	}
	if err := validateSubject(req); err != nil {
		return err
	}
	if req.CallbackURL != "" {
		if err := validateCallbackURL(req.CallbackURL); err != nil {
			return err
		}
	}
	if !validEntries(req.Principal.Attributes) || !validEntries(req.Action.Details) {
		return NewProtocolError(CodeMalformedRequest, "labeled entry keys must be unique within their array")
	}
	return nil
}

// validateFields checks required-field presence, id charset, action.name
// length, and the closed category registry.
func validateFields(req *AuthorizationRequest) *ProtocolError {
	switch {
	case req.RequestID == "":
		return NewProtocolError(CodeMalformedRequest, "missing requestId")
	case req.SenderID == "":
		return NewProtocolError(CodeMalformedRequest, "missing senderId")
	case req.RecipientID == "":
		return NewProtocolError(CodeMalformedRequest, "missing recipientId")
	case req.Timestamp == "":
		return NewProtocolError(CodeMalformedRequest, "missing timestamp")
	case req.ExpiresAt == "":
		return NewProtocolError(CodeMalformedRequest, "missing expiresAt")
	case req.Action.Type == "":
		return NewProtocolError(CodeMalformedRequest, "missing action.type")
	case req.Action.Category == "":
		return NewProtocolError(CodeMalformedRequest, "missing action.category")
	case req.Action.Summary == "":
		return NewProtocolError(CodeMalformedRequest, "missing action.summary")
	case req.Principal.Subject == "":
		return NewProtocolError(CodeMalformedRequest, "missing principal.subject")
	case !validKeyID(req.RequestID):
		return NewProtocolError(CodeMalformedRequest, "requestId has invalid characters or is too long")
	case !validKeyID(req.SenderID):
		return NewProtocolError(CodeMalformedRequest, "senderId has invalid characters or is too long")
	case utf8.RuneCountInString(req.Action.Name) > MaxActionNameLen:
		return NewProtocolError(CodeMalformedRequest, fmt.Sprintf("action.name is longer than %d characters", MaxActionNameLen))
	}
	if !IsValidCategory(req.Action.Category) {
		return NewProtocolError(CodeUnknownCategory, "unknown action.category: "+req.Action.Category)
	}
	return nil
}

// validKeyID matches the hub's requestId/senderId charset: non-empty, at
// most MaxKeyIDLen bytes, printable ASCII, no '#' (a sort-key delimiter on
// the hub side that would let one id's key range straddle another's).
func validKeyID(id string) bool {
	if id == "" || len(id) > MaxKeyIDLen {
		return false
	}
	for i := range len(id) {
		if c := id[i]; c == '#' || c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// validateTiming checks that timestamp and expiresAt parse, timestamp skew
// against now, then operator-chain depth.
func validateTiming(req *AuthorizationRequest, now time.Time) *ProtocolError {
	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		return NewProtocolError(CodeTimestampOutOfRange, "timestamp is not RFC3339")
	}
	if d := now.Sub(ts); d > MaxClockSkew || d < -MaxClockSkew {
		return NewProtocolError(CodeTimestampOutOfRange, "timestamp skew exceeds 5m")
	}
	if _, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil {
		return NewProtocolError(CodeMalformedRequest, "expiresAt is not RFC3339")
	}

	depth := 0
	for p := req.Principal.Operator; p != nil; p = p.Operator {
		depth++
		if depth > MaxOperatorDepth {
			return NewProtocolError(CodeOperatorDepthExceeded, "operator chain deeper than 5")
		}
	}
	return nil
}

// validateSubject checks principal.subject is a valid individual NameID, and
// action.approver, if set, is a valid NameID.
func validateSubject(req *AuthorizationRequest) *ProtocolError {
	n, err := ParseNameID(req.Principal.Subject)
	if err != nil || !n.IsIndividual() {
		return NewProtocolError(CodeMalformedRequest, "principal.subject must be an individual NameID")
	}
	if req.Action.Approver != "" && !ValidNameID(req.Action.Approver) {
		return NewProtocolError(CodeMalformedRequest, "action.approver is not a valid NameID")
	}
	return nil
}

// validateCallbackURL enforces https, or http to a loopback host as a dev allowance.
func validateCallbackURL(raw string) *ProtocolError {
	u, err := url.Parse(raw)
	if err != nil {
		return NewProtocolError(CodeInvalidCallbackURL, "callbackUrl is not a valid URL")
	}
	if !httpsOrLoopback(u) {
		return NewProtocolError(CodeInvalidCallbackURL, "callbackUrl must be https, or http to localhost/127.0.0.1")
	}
	return nil
}

// httpsOrLoopback is the scheme rule shared by callbackUrl and hub host:
// https, or http to a loopback host as a dev allowance.
func httpsOrLoopback(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && loopbackRe.MatchString(u.Hostname())
}
