// A minimal StepAuth service provider: it establishes a signing identity,
// writes the metadata a hub administrator registers, and produces a signed
// authorization request.
//
//	go run .
//
// Artifacts land in ./out. Re-running reuses the existing keyset rather than
// minting a new one, because a new keyset means registering with the hub again.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"time"

	"github.com/splitsecure/apis/sdk/go/stepauth"
)

const (
	outDir       = "out"
	keysetFile   = "out/sp-keyset.json"   // private: never leaves the SP
	metadataFile = "out/sp-metadata.json" // public: handed to a hub administrator
	envelopeFile = "out/request-envelope.json"

	spEntity    = "sp.example.com"
	hubEntity   = "acme.hub.example.com"
	callbackURL = "https://sp.example.com/stepauth/callback"
)

// spMetadata is what a hub administrator needs to register this SP: who it is,
// which keys verify its envelopes, and where decisions are delivered.
type spMetadata struct {
	Entity      string            `json:"entity"`
	Keysets     []stepauth.Keyset `json:"keysets"`
	CallbackURL string            `json:"callbackUrl"`
}

func main() {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		log.Fatalf("creating %s: %v", outDir, err)
	}

	keyset, err := establishIdentity()
	if err != nil {
		log.Fatalf("establishing signing identity: %v", err)
	}

	metadata := spMetadata{
		Entity:      spEntity,
		Keysets:     []stepauth.Keyset{keyset.PublicKeyset()},
		CallbackURL: callbackURL,
	}
	if err := writeJSON(metadataFile, metadata, 0o644); err != nil {
		log.Fatalf("writing metadata: %v", err)
	}
	fmt.Printf("%s  register this with the hub\n", metadataFile)

	envelope, err := signRequest(keyset)
	if err != nil {
		log.Fatalf("signing request: %v", err)
	}
	if err := os.WriteFile(envelopeFile, envelope, 0o600); err != nil {
		log.Fatalf("writing envelope: %v", err)
	}
	fmt.Printf("%s  %d bytes, POST this to the hub\n", envelopeFile, len(envelope))

	// Retain the payload bytes exactly as signed. The hub's decision carries a
	// digest over them, and re-encoding the request would make that digest
	// unverifiable.
	payload, err := stepauth.VerifyEnvelope(envelope, []stepauth.Keyset{keyset.PublicKeyset()})
	if err != nil {
		log.Fatalf("verifying own envelope: %v", err)
	}
	fmt.Printf("\nsigned payload verifies, %d bytes to retain for the decision digest\n", len(payload))
}

// establishIdentity reads the persisted signing identity, minting one on first
// run. The whole keyset is private material.
func establishIdentity() (*stepauth.SigningKeyset, error) {
	stored, err := os.ReadFile(keysetFile)
	switch {
	case err == nil:
		var keyset stepauth.SigningKeyset
		if err := json.Unmarshal(stored, &keyset); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", keysetFile, err)
		}
		fmt.Printf("%s  loaded existing identity %q\n", keysetFile, keyset.KeysetID)
		return &keyset, nil

	case errors.Is(err, fs.ErrNotExist):
		keyset, err := stepauth.GenerateKeyset("ks_" + time.Now().UTC().Format("20060102150405"))
		if err != nil {
			return nil, err
		}
		if err := writeJSON(keysetFile, keyset, 0o600); err != nil {
			return nil, err
		}
		fmt.Printf("%s  minted identity %q, keep this private\n", keysetFile, keyset.KeysetID)
		return keyset, nil

	default:
		return nil, err
	}
}

// signRequest builds an authorization request and signs it into an envelope.
func signRequest(keyset *stepauth.SigningKeyset) ([]byte, error) {
	now := time.Now().UTC()
	request := map[string]any{
		"requestId":   "req_" + now.Format("20060102150405"),
		"senderId":    spEntity,
		"recipientId": hubEntity,
		"timestamp":   now.Format(time.RFC3339),
		"expiresAt":   now.Add(30 * time.Minute).Format(time.RFC3339),
		"principal":   map[string]any{"subject": "email:operator@example.com"},
		"action": map[string]any{
			"type":     "com.example.database.drop",
			"category": "data.delete",
			"name":     "Drop the production database",
			"summary":  "Permanently deletes the production database and every backup older than 24 hours.",
		},
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return stepauth.SignEnvelope(keyset, payload)
}

func writeJSON(path string, v any, mode fs.FileMode) error {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), mode)
}
