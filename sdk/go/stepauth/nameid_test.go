package stepauth

import "testing"

func TestParseNameIDAccepts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want NameID
	}{
		{"email", "email:a@b.com", NameID{Type: "email", Value: "a@b.com"}},
		{"persistent", "persistent:p_123", NameID{Type: "persistent", Value: "p_123"}},
		{"group", "group:g_123", NameID{Type: "group", Value: "g_123"}},
		{"policy", "policy:pol_123", NameID{Type: "policy", Value: "pol_123"}},
		{"value with colon", "email:a:b@c.com", NameID{Type: "email", Value: "a:b@c.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNameID(tt.in)
			if err != nil {
				t.Fatalf("ParseNameID(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseNameID(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseNameIDRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"no colon", "email"},
		{"unregistered type", "phone:555-1234"},
		{"empty value", "email:"},
		{"empty string", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseNameID(tt.in); err == nil {
				t.Errorf("ParseNameID(%q) accepted, want error", tt.in)
			}
			if ValidNameID(tt.in) {
				t.Errorf("ValidNameID(%q) = true, want false", tt.in)
			}
		})
	}
}

func TestIsIndividual(t *testing.T) {
	individuals := []string{"email:a@b.com", "persistent:p_1"}
	for _, s := range individuals {
		n, err := ParseNameID(s)
		if err != nil {
			t.Fatalf("ParseNameID(%q): %v", s, err)
		}
		if !n.IsIndividual() {
			t.Errorf("%q.IsIndividual() = false, want true", s)
		}
	}

	nonIndividuals := []string{"group:g_1", "policy:pol_1"}
	for _, s := range nonIndividuals {
		n, err := ParseNameID(s)
		if err != nil {
			t.Fatalf("ParseNameID(%q): %v", s, err)
		}
		if n.IsIndividual() {
			t.Errorf("%q.IsIndividual() = true, want false", s)
		}
	}
}

func TestNameIDConstructors(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{Email("a@b.com"), "email:a@b.com"},
		{Persistent("p_1"), "persistent:p_1"},
		{GroupID("g_1"), "group:g_1"},
		{PolicyID("pol_1"), "policy:pol_1"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got %q, want %q", tt.got, tt.want)
		}
		if !ValidNameID(tt.got) {
			t.Errorf("constructed NameID %q is not valid", tt.got)
		}
	}
}

func TestNameIDStringRoundTrips(t *testing.T) {
	n, err := ParseNameID("email:a@b.com")
	if err != nil {
		t.Fatalf("ParseNameID: %v", err)
	}
	if got := n.String(); got != "email:a@b.com" {
		t.Errorf("String() = %q, want %q", got, "email:a@b.com")
	}
}
