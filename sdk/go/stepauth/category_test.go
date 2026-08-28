package stepauth

import "testing"

func TestIsValidCategoryAccepts(t *testing.T) {
	for c := range categoryRegistry {
		if !IsValidCategory(c) {
			t.Errorf("IsValidCategory(%q) = false, want true", c)
		}
	}
}

func TestIsValidCategoryRejectsOutsideRegistry(t *testing.T) {
	tests := []string{"", "data", "data.readx", "DATA.READ", "unknown.category"}
	for _, c := range tests {
		if IsValidCategory(c) {
			t.Errorf("IsValidCategory(%q) = true, want false", c)
		}
	}
}

func TestCategoryRegistryHas17Entries(t *testing.T) {
	if got := len(categoryRegistry); got != 17 {
		t.Errorf("categoryRegistry has %d entries, want 17", got)
	}
}
