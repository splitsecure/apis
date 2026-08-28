package stepauth

import (
	"encoding/json"
	"testing"
)

func TestEntryStringValue(t *testing.T) {
	e := Entry("email", "Email", "a@b.com")

	got, ok := e.StringValue()
	if !ok {
		t.Fatalf("StringValue() ok = false, want true")
	}
	if got != "a@b.com" {
		t.Errorf("StringValue() = %q, want %q", got, "a@b.com")
	}
	if _, ok := e.Children(); ok {
		t.Errorf("Children() ok = true on a string entry")
	}
}

func TestGroupChildren(t *testing.T) {
	g := Group("address", "Address", Entry("city", "City", "Ottawa"), Entry("zip", "Zip", "K1A"))

	children, ok := g.Children()
	if !ok {
		t.Fatalf("Children() ok = false, want true")
	}
	if len(children) != 2 || children[0].Key != "city" || children[1].Key != "zip" {
		t.Errorf("Children() = %+v, want city then zip", children)
	}
	if _, ok := g.StringValue(); ok {
		t.Errorf("StringValue() ok = true on a group entry")
	}
}

func TestGroupWithNoChildrenMarshalsAsEmptyArray(t *testing.T) {
	raw, err := json.Marshal(Group("k", "L"))
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	var shape struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if string(shape.Value) != "[]" {
		t.Errorf(`value = %s, want "[]"`, shape.Value)
	}
}

func TestEntries(t *testing.T) {
	got := Entries(Entry("a", "A", "1"), Entry("b", "B", "2"))
	if len(got) != 2 {
		t.Fatalf("Entries() returned %d entries, want 2", len(got))
	}
}

func TestValidEntriesRejectsDuplicateKeys(t *testing.T) {
	entries := []LabeledEntry{Entry("dup", "A", "1"), Entry("dup", "B", "2")}
	if validEntries(entries) {
		t.Error("validEntries accepted duplicate top-level keys")
	}
}

func TestValidEntriesAcceptsDistinctKeys(t *testing.T) {
	entries := []LabeledEntry{Entry("a", "A", "1"), Entry("b", "B", "2")}
	if !validEntries(entries) {
		t.Error("validEntries rejected distinct top-level keys")
	}
}

func TestValidEntriesRejectsDuplicateKeysInNestedGroup(t *testing.T) {
	entries := []LabeledEntry{
		Group("g", "G", Entry("dup", "A", "1"), Entry("dup", "B", "2")),
	}
	if validEntries(entries) {
		t.Error("validEntries accepted duplicate keys nested inside a group")
	}
}

func TestValidEntriesAllowsSameKeyInSiblingGroups(t *testing.T) {
	// Uniqueness is per array, not global: the same key in two different
	// groups' children does not collide.
	entries := []LabeledEntry{
		Group("g1", "G1", Entry("dup", "A", "1")),
		Group("g2", "G2", Entry("dup", "B", "2")),
	}
	if !validEntries(entries) {
		t.Error("validEntries rejected the same key reused across sibling groups")
	}
}

func TestValidEntriesAcceptsCamelCaseKey(t *testing.T) {
	if !validEntries([]LabeledEntry{Entry("userId", "User ID", "1")}) {
		t.Error("validEntries rejected a camelCase key")
	}
}
