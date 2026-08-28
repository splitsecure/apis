package stepauth

import (
	"encoding/json"
)

// Entry builds a LabeledEntry with a plain string value.
func Entry(key, label, value string) LabeledEntry {
	raw, err := json.Marshal(value)
	if err != nil {
		raw = json.RawMessage(`""`)
	}
	return LabeledEntry{Key: key, Label: label, Value: raw}
}

// Group builds a LabeledEntry with nested child entries.
func Group(key, label string, children ...LabeledEntry) LabeledEntry {
	if children == nil {
		children = []LabeledEntry{}
	}
	// Marshal fails only on a hand-built child holding invalid RawMessage.
	// Emitting null there would read to the hub as an empty-string entry
	// rather than an empty group, so fall back to an empty array.
	raw, err := json.Marshal(children)
	if err != nil {
		raw = json.RawMessage("[]")
	}
	return LabeledEntry{Key: key, Label: label, Value: raw}
}

// Entries is a convenience that returns its arguments as a slice.
func Entries(entries ...LabeledEntry) []LabeledEntry { return entries }

// StringValue returns the entry's string value, or ok=false if it is a group.
func (e LabeledEntry) StringValue() (value string, ok bool) {
	if err := json.Unmarshal(e.Value, &value); err != nil {
		return "", false
	}
	return value, true
}

// Children returns the entry's nested entries, or ok=false if it holds a string.
func (e LabeledEntry) Children() (children []LabeledEntry, ok bool) {
	if err := json.Unmarshal(e.Value, &children); err != nil {
		return nil, false
	}
	return children, true
}

// validEntries reports whether every entry has a unique key, recursing into
// groups (keys are unique per array, not globally).
func validEntries(entries []LabeledEntry) bool {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.Key] {
			return false
		}
		seen[e.Key] = true
		children, isGroup := e.Children()
		if isGroup {
			if !validEntries(children) {
				return false
			}
			continue
		}
		// Value is a leaf string or a child array. Any other JSON shape is
		// not an entry the hub can render.
		if _, isLeaf := e.StringValue(); !isLeaf {
			return false
		}
	}
	return true
}
