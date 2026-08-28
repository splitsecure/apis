package stepauth

import (
	"fmt"
	"strings"
)

// NameID types. Email and Persistent are individuals.
const (
	NameIDEmail      = "email"
	NameIDPersistent = "persistent"
	NameIDGroup      = "group"
	NameIDPolicy     = "policy"
)

// NameID is a parsed typed identifier "type:value".
type NameID struct {
	Type  string
	Value string
}

// ParseNameID splits s on the FIRST colon; type must be registered and value non-empty.
func ParseNameID(s string) (NameID, error) {
	t, v, ok := strings.Cut(s, ":")
	if !ok {
		return NameID{}, fmt.Errorf("stepauth: nameid %q: missing ':'", s)
	}
	switch t {
	case NameIDEmail, NameIDPersistent, NameIDGroup, NameIDPolicy:
	default:
		return NameID{}, fmt.Errorf("stepauth: nameid %q: unregistered type %q", s, t)
	}
	if v == "" {
		return NameID{}, fmt.Errorf("stepauth: nameid %q: empty value", s)
	}
	return NameID{Type: t, Value: v}, nil
}

// String renders the NameID to wire form.
func (n NameID) String() string { return n.Type + ":" + n.Value }

// IsIndividual reports whether the NameID is a single person, the only kind
// allowed as principal.subject.
func (n NameID) IsIndividual() bool {
	return n.Type == NameIDEmail || n.Type == NameIDPersistent
}

// ValidNameID reports whether s parses as a well-formed NameID.
func ValidNameID(s string) bool {
	_, err := ParseNameID(s)
	return err == nil
}

// Email returns an email-typed NameID in wire form, e.g. Email("a@b.com") == "email:a@b.com".
func Email(addr string) string { return NameIDEmail + ":" + addr }

// Persistent returns a persistent-typed NameID in wire form.
func Persistent(id string) string { return NameIDPersistent + ":" + id }

// GroupID returns a group-typed NameID in wire form.
func GroupID(id string) string { return NameIDGroup + ":" + id }

// PolicyID returns a policy-typed NameID in wire form.
func PolicyID(id string) string { return NameIDPolicy + ":" + id }
