package stepauth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validRequest() *AuthorizationRequest {
	now := time.Now().UTC()
	return &AuthorizationRequest{
		RequestID:   "req_1",
		SenderID:    "sp.example.com",
		RecipientID: "hub.example.com",
		Timestamp:   now.Format(time.RFC3339),
		ExpiresAt:   now.Add(30 * time.Minute).Format(time.RFC3339),
		Principal:   Principal{Subject: Email("a@b.com")},
		Action: Action{
			Type:     "sp.example.deploy",
			Category: CategoryCodeDeploy,
			Summary:  "Deploy the payments service",
		},
	}
}

func TestActionNameOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(validRequest().Action)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	if strings.Contains(string(raw), `"name"`) {
		t.Errorf("empty action.name was not omitted: %s", raw)
	}
}

func TestActionNameIncludedWhenSet(t *testing.T) {
	a := validRequest().Action
	a.Name = "Deploy payments"

	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	if !strings.Contains(string(raw), `"name":"Deploy payments"`) {
		t.Errorf("action.name missing from marshaled output: %s", raw)
	}
}

func TestPrincipalOperatorOmittedWhenNil(t *testing.T) {
	raw, err := json.Marshal(Principal{Subject: Email("a@b.com")})
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	if strings.Contains(string(raw), `"operator"`) {
		t.Errorf("nil operator was not omitted: %s", raw)
	}
}

func TestLabeledEntryRoundTripsStringValue(t *testing.T) {
	entry := Entry("region", "Region", "us-east-2")

	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	var got LabeledEntry
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	v, ok := got.StringValue()
	if !ok || v != "us-east-2" {
		t.Errorf("StringValue() = (%q, %v), want (%q, true)", v, ok, "us-east-2")
	}
}

func TestAuthorizationRequestRoundTrips(t *testing.T) {
	want := validRequest()
	want.Action.Details = Entries(Entry("env", "Environment", "prod"))

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	var got AuthorizationRequest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if got.RequestID != want.RequestID || got.Action.Category != want.Action.Category {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, want)
	}
}
