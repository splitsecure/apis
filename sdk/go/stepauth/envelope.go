package stepauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Signature is a keyset signature: the signing keyset's id plus one signature
// per component key, ordered by keyset index.
type Signature struct {
	KeysetID   string   `json:"keysetId"`
	Signatures []string `json:"signatures"`
}

// Envelope is the signed wrapper every protocol message travels in. Payload is
// base64 of the raw message bytes, and signatures cover those exact bytes.
type Envelope struct {
	Payload   string    `json:"payload"`
	Signature Signature `json:"signature"`
}

// SignEnvelope signs payload with every key in the keyset and returns the
// marshaled envelope. Signatures cover the payload bytes exactly as they will
// be transmitted; nothing between here and the wire may reserialize them.
func SignEnvelope(ks *SigningKeyset, payload []byte) ([]byte, error) {
	if err := ks.validate(); err != nil {
		return nil, err
	}

	sigs := make([]string, len(ks.Keys))
	for i, key := range ks.Keys {
		sig, err := signComponent(key, payload)
		if err != nil {
			return nil, fmt.Errorf("stepauth: signing with key %d (%s): %w", key.Idx, key.Alg, err)
		}
		sigs[i] = base64.StdEncoding.EncodeToString(sig)
	}

	return json.Marshal(Envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: Signature{KeysetID: ks.KeysetID, Signatures: sigs},
	})
}

// VerifyEnvelope resolves the envelope's keysetId against the signer's active
// keysets and verifies all-of, returning the decoded payload. Every failure
// yields ErrInvalidSignature.
func VerifyEnvelope(envelopeJSON []byte, keysets []Keyset) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope is not valid json", ErrInvalidSignature)
	}

	keyset := keysetByID(keysets, env.Signature.KeysetID)
	if keyset == nil {
		return nil, ErrInvalidSignature
	}
	// Positive check: the keyset must carry exactly the v1 algorithms in
	// order. That subsumes both a zero-key keyset (fails the length check)
	// and a duplicate-algorithm keyset (fails the order check).
	if err := validateKeyset(*keyset); err != nil {
		return nil, ErrInvalidSignature
	}
	if len(env.Signature.Signatures) != len(keyset.Keys) {
		return nil, ErrInvalidSignature
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	for i, kk := range keyset.Keys {
		sig, err := base64.StdEncoding.DecodeString(env.Signature.Signatures[i])
		if err != nil {
			return nil, ErrInvalidSignature
		}
		pub, err := base64.StdEncoding.DecodeString(kk.Pub)
		if err != nil {
			return nil, ErrInvalidSignature
		}
		if err := verifyComponent(kk.Alg, pub, payload, sig); err != nil {
			return nil, ErrInvalidSignature
		}
	}
	return payload, nil
}

// DecodeEnvelopePayload base64-decodes a payload WITHOUT verifying the
// signature. Only for routing a message to the state needed to verify it; the
// result is untrusted until VerifyEnvelope has run.
func DecodeEnvelopePayload(envelopeJSON []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("stepauth: parsing envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("stepauth: envelope payload is not valid base64: %w", err)
	}
	return payload, nil
}

func keysetByID(keysets []Keyset, id string) *Keyset {
	for i := range keysets {
		if keysets[i].KeysetID == id {
			return &keysets[i]
		}
	}
	return nil
}
