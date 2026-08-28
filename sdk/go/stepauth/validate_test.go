package stepauth

import (
	"errors"
	"strings"
	"testing"
)

// protocolCode recovers the wire code from a Validate error, which is an
// error interface rather than a concrete type.
func protocolCode(t *testing.T, err error) Code {
	t.Helper()
	var pe *ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("error is not a *ProtocolError: %v", err)
	}
	return pe.Code
}

func TestValidateAcceptsWellFormedRequest(t *testing.T) {
	if err := Validate(validRequest()); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestValidateRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthorizationRequest)
	}{
		{"requestId", func(r *AuthorizationRequest) { r.RequestID = "" }},
		{"senderId", func(r *AuthorizationRequest) { r.SenderID = "" }},
		{"recipientId", func(r *AuthorizationRequest) { r.RecipientID = "" }},
		{"timestamp", func(r *AuthorizationRequest) { r.Timestamp = "" }},
		{"expiresAt", func(r *AuthorizationRequest) { r.ExpiresAt = "" }},
		{"action.type", func(r *AuthorizationRequest) { r.Action.Type = "" }},
		{"action.category", func(r *AuthorizationRequest) { r.Action.Category = "" }},
		{"action.summary", func(r *AuthorizationRequest) { r.Action.Summary = "" }},
		{"principal.subject", func(r *AuthorizationRequest) { r.Principal.Subject = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validRequest()
			tt.mutate(req)
			if err := Validate(req); err == nil {
				t.Errorf("Validate() accepted a request missing %s", tt.name)
			}
		})
	}
}

func TestValidateRejectsKeyIDWithHash(t *testing.T) {
	req := validRequest()
	req.RequestID = "req#1"
	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted a requestId containing '#'")
	}
	if code := protocolCode(t, err); code != CodeMalformedRequest {
		t.Errorf("Code = %q, want %q", code, CodeMalformedRequest)
	}
}

func TestValidateRejectsOverlongKeyID(t *testing.T) {
	req := validRequest()
	req.SenderID = strings.Repeat("a", MaxKeyIDLen+1)
	if Validate(req) == nil {
		t.Error("Validate() accepted a senderId over MaxKeyIDLen")
	}
}

func TestValidateAcceptsMaxLengthKeyID(t *testing.T) {
	req := validRequest()
	req.SenderID = strings.Repeat("a", MaxKeyIDLen)
	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for a MaxKeyIDLen senderId", err)
	}
}

func TestValidateRejectsNonPrintableKeyID(t *testing.T) {
	req := validRequest()
	req.RequestID = "req\x01id"
	if Validate(req) == nil {
		t.Error("Validate() accepted a requestId with a non-printable byte")
	}
}

// TestValidateActionNameCountsRunesNotBytes is the known cross-language
// divergence risk: a byte-length check would reject a multi-byte name well
// under the 120-rune limit.
func TestValidateActionNameCountsRunesNotBytes(t *testing.T) {
	req := validRequest()
	req.Action.Name = strings.Repeat("é", 120) // 120 runes, 240 bytes

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for a 120-rune multi-byte name", err)
	}
}

func TestValidateRejectsActionNameOver120Runes(t *testing.T) {
	req := validRequest()
	req.Action.Name = strings.Repeat("é", 121)

	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted a 121-rune action.name")
	}
	if code := protocolCode(t, err); code != CodeMalformedRequest {
		t.Errorf("Code = %q, want %q", code, CodeMalformedRequest)
	}
}

func TestValidateRejectsUnknownCategory(t *testing.T) {
	req := validRequest()
	req.Action.Category = "not.a.real.category"

	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted an unregistered category")
	}
	if code := protocolCode(t, err); code != CodeUnknownCategory {
		t.Errorf("Code = %q, want %q", code, CodeUnknownCategory)
	}
}

func TestValidateAcceptsEveryRegisteredCategory(t *testing.T) {
	for c := range categoryRegistry {
		req := validRequest()
		req.Action.Category = c
		if err := Validate(req); err != nil {
			t.Errorf("Validate() = %v, want nil for category %q", err, c)
		}
	}
}

func TestValidateRejectsNonIndividualSubject(t *testing.T) {
	req := validRequest()
	req.Principal.Subject = GroupID("g_1")

	if Validate(req) == nil {
		t.Error("Validate() accepted a group NameID as principal.subject")
	}
}

func TestValidateAcceptsPersistentSubject(t *testing.T) {
	req := validRequest()
	req.Principal.Subject = Persistent("p_1")

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for a persistent subject", err)
	}
}

func TestValidateRejectsMalformedApprover(t *testing.T) {
	req := validRequest()
	req.Action.Approver = "not-a-nameid"

	if Validate(req) == nil {
		t.Error("Validate() accepted a malformed action.approver")
	}
}

func TestValidateAcceptsWellFormedApprover(t *testing.T) {
	req := validRequest()
	req.Action.Approver = GroupID("g_reviewers")

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for a well-formed group approver", err)
	}
}

func TestValidateRejectsOperatorDepthOver5(t *testing.T) {
	req := validRequest()
	p := &req.Principal
	for range 6 {
		p.Operator = &Principal{Subject: Email("op@b.com")}
		p = p.Operator
	}

	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted an operator chain deeper than 5")
	}
	if code := protocolCode(t, err); code != CodeOperatorDepthExceeded {
		t.Errorf("Code = %q, want %q", code, CodeOperatorDepthExceeded)
	}
}

func TestValidateAcceptsOperatorDepthOf5(t *testing.T) {
	req := validRequest()
	p := &req.Principal
	for range 5 {
		p.Operator = &Principal{Subject: Email("op@b.com")}
		p = p.Operator
	}

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for an operator chain of depth 5", err)
	}
}

func TestValidateRejectsBadTimestamp(t *testing.T) {
	req := validRequest()
	req.Timestamp = "not-a-timestamp"

	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted a non-RFC3339 timestamp")
	}
	if code := protocolCode(t, err); code != CodeTimestampOutOfRange {
		t.Errorf("Code = %q, want %q", code, CodeTimestampOutOfRange)
	}
}

func TestValidateRejectsBadExpiresAt(t *testing.T) {
	req := validRequest()
	req.ExpiresAt = "not-a-timestamp"

	if Validate(req) == nil {
		t.Error("Validate() accepted a non-RFC3339 expiresAt")
	}
}

func TestValidateRejectsClockSkewOver5Minutes(t *testing.T) {
	req := validRequest()
	req.Timestamp = "2020-01-01T00:00:00Z" // far in the past relative to time.Now

	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted a timestamp with excessive skew")
	}
	if code := protocolCode(t, err); code != CodeTimestampOutOfRange {
		t.Errorf("Code = %q, want %q", code, CodeTimestampOutOfRange)
	}
}

func TestValidateCallbackURLAcceptsHTTPS(t *testing.T) {
	req := validRequest()
	req.CallbackURL = "https://sp.example.com/callback"

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for an https callbackUrl", err)
	}
}

func TestValidateCallbackURLAcceptsLoopback(t *testing.T) {
	for _, u := range []string{"http://localhost/callback", "http://127.0.0.1:8080/callback"} {
		req := validRequest()
		req.CallbackURL = u
		if err := Validate(req); err != nil {
			t.Errorf("Validate() = %v, want nil for loopback callbackUrl %q", err, u)
		}
	}
}

func TestValidateCallbackURLRejectsPlainHTTP(t *testing.T) {
	req := validRequest()
	req.CallbackURL = "http://sp.example.com/callback"

	err := Validate(req)
	if err == nil {
		t.Fatal("Validate() accepted a non-loopback http callbackUrl")
	}
	if code := protocolCode(t, err); code != CodeInvalidCallbackURL {
		t.Errorf("Code = %q, want %q", code, CodeInvalidCallbackURL)
	}
}

func TestValidateAllowsEmptyCallbackURL(t *testing.T) {
	req := validRequest()
	req.CallbackURL = ""

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for an omitted callbackUrl", err)
	}
}

func TestValidateRejectsDuplicateAttributeKeys(t *testing.T) {
	req := validRequest()
	req.Principal.Attributes = Entries(Entry("dup", "A", "1"), Entry("dup", "B", "2"))

	if Validate(req) == nil {
		t.Error("Validate() accepted duplicate principal.attributes keys")
	}
}

func TestValidateAcceptsDistinctAttributeKeys(t *testing.T) {
	req := validRequest()
	req.Principal.Attributes = Entries(Entry("dept", "Department", "eng"), Entry("role", "Role", "admin"))

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for distinct attribute keys", err)
	}
}

func TestValidateAcceptsCamelCaseDetailKey(t *testing.T) {
	req := validRequest()
	req.Action.Details = Entries(Entry("userId", "User ID", "1"))

	if err := Validate(req); err != nil {
		t.Errorf("Validate() = %v, want nil for a camelCase action.details key", err)
	}
}
