package stepauth

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Signature-algorithm wire names, appearing verbatim as a component's alg.
const (
	AlgEd25519 = "ed25519"
	AlgMLDSA65 = "ml-dsa-65"
)

// KeysetAlgs returns the v1 hybrid pair in index order. Verification is
// all-of: every component must verify, so the pair degrades no further than
// its stronger half if either primitive is broken.
func KeysetAlgs() []string { return []string{AlgEd25519, AlgMLDSA65} }

// ErrInvalidSignature is any envelope verification failure. The cause is
// deliberately not distinguished: a caller that can tell "wrong keyset" from
// "bad signature" learns something an attacker also learns.
var ErrInvalidSignature = errors.New("stepauth: invalid signature")

// SigningKey is one component of a keyset, holding private material. Priv is
// the algorithm's expanded private key.
type SigningKey struct {
	Idx  int    `json:"idx"`
	Alg  string `json:"alg"`
	Pub  []byte `json:"pub"`
	Priv []byte `json:"priv"`
}

// SigningKeyset is an SP's signing identity, named by an opaque immutable id.
type SigningKeyset struct {
	KeysetID string       `json:"keysetId"`
	Keys     []SigningKey `json:"keys"`
}

// String returns a redacted form; private key material is never printed.
func (k SigningKey) String() string {
	return fmt.Sprintf("SigningKey{idx:%d alg:%s pub:%d bytes priv:REDACTED}", k.Idx, k.Alg, len(k.Pub))
}

// String returns a redacted form; private key material is never printed.
func (ks SigningKeyset) String() string {
	return fmt.Sprintf("SigningKeyset{keysetId:%s keys:%d}", ks.KeysetID, len(ks.Keys))
}

// KeysetKey is one component public key as published in a metadata document.
type KeysetKey struct {
	Idx int    `json:"idx"`
	Alg string `json:"alg"`
	Pub string `json:"pub"`
}

// Keyset is the public wire form of a signing identity.
type Keyset struct {
	KeysetID string      `json:"keysetId"`
	Keys     []KeysetKey `json:"keys"`
}

// GenerateKeyset mints a keyset carrying one fresh component per v1 algorithm.
func GenerateKeyset(keysetID string) (*SigningKeyset, error) {
	if keysetID == "" {
		return nil, errors.New("stepauth: keysetId is required")
	}

	ks := &SigningKeyset{KeysetID: keysetID, Keys: make([]SigningKey, 0, len(KeysetAlgs()))}
	for idx, alg := range KeysetAlgs() {
		pub, priv, err := generateComponent(alg)
		if err != nil {
			return nil, fmt.Errorf("stepauth: generating %s key: %w", alg, err)
		}
		ks.Keys = append(ks.Keys, SigningKey{Idx: idx, Alg: alg, Pub: pub, Priv: priv})
	}
	return ks, nil
}

func generateComponent(alg string) (pub, priv []byte, err error) {
	switch alg {
	case AlgEd25519:
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return p, s, nil

	case AlgMLDSA65:
		p, s, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return p.Bytes(), s.Bytes(), nil
	}
	return nil, nil, fmt.Errorf("unsupported algorithm %q", alg)
}

// KeyFromSeed expands an algorithm seed into its public key. Both v1
// algorithms derive deterministically from a seed; keysets themselves are
// stored expanded, so nothing here touches persistence.
func KeyFromSeed(alg string, seed []byte) ([]byte, error) {
	switch alg {
	case AlgEd25519:
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("stepauth: ed25519 seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub, _ := priv.Public().(ed25519.PublicKey)
		return pub, nil

	case AlgMLDSA65:
		if len(seed) != mldsa65.SeedSize {
			return nil, fmt.Errorf("stepauth: ml-dsa-65 seed is %d bytes, want %d", len(seed), mldsa65.SeedSize)
		}
		var s [mldsa65.SeedSize]byte
		copy(s[:], seed)
		pub, _ := mldsa65.NewKeyFromSeed(&s)
		raw, err := pub.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("stepauth: marshaling ml-dsa-65 public key: %w", err)
		}
		return raw, nil
	}
	return nil, fmt.Errorf("stepauth: unsupported algorithm %q", alg)
}

// PublicKeyset returns the metadata form of the keyset, private material
// stripped.
func (ks *SigningKeyset) PublicKeyset() Keyset {
	if ks == nil {
		return Keyset{}
	}
	out := Keyset{KeysetID: ks.KeysetID, Keys: make([]KeysetKey, len(ks.Keys))}
	for i, k := range ks.Keys {
		out.Keys[i] = KeysetKey{Idx: k.Idx, Alg: k.Alg, Pub: base64.StdEncoding.EncodeToString(k.Pub)}
	}
	return out
}

// validateKeyset reports whether ks carries the v1 algorithms in index
// order. All-of over a partial keyset is all-of over whatever it happens to
// carry, so a keyset missing a component downgrades verification silently.
func validateKeyset(ks Keyset) error {
	algs := KeysetAlgs()
	if len(ks.Keys) != len(algs) {
		return fmt.Errorf("stepauth: keyset %q must carry the v1 algorithms in order", ks.KeysetID)
	}
	for i, alg := range algs {
		if ks.Keys[i].Alg != alg {
			return fmt.Errorf("stepauth: keyset %q must carry the v1 algorithms in order", ks.KeysetID)
		}
	}
	return nil
}

func (ks *SigningKeyset) validate() error {
	if ks == nil || len(ks.Keys) == 0 {
		return errors.New("stepauth: signing keyset is empty")
	}
	if ks.KeysetID == "" {
		return errors.New("stepauth: signing keyset has no keysetId")
	}
	algs := KeysetAlgs()
	if len(ks.Keys) != len(algs) {
		return errors.New("stepauth: keyset must carry the v1 algorithms in order")
	}
	for i, alg := range algs {
		if ks.Keys[i].Alg != alg {
			return errors.New("stepauth: keyset must carry the v1 algorithms in order")
		}
	}
	return nil
}

func signComponent(key SigningKey, msg []byte) ([]byte, error) {
	switch key.Alg {
	case AlgEd25519:
		if len(key.Priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("stepauth: ed25519 private key is %d bytes, want %d", len(key.Priv), ed25519.PrivateKeySize)
		}
		return ed25519.Sign(ed25519.PrivateKey(key.Priv), msg), nil

	case AlgMLDSA65:
		var priv mldsa65.PrivateKey
		if err := priv.UnmarshalBinary(key.Priv); err != nil {
			return nil, fmt.Errorf("stepauth: parsing ml-dsa-65 private key: %w", err)
		}
		return priv.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	return nil, fmt.Errorf("stepauth: unsupported algorithm %q", key.Alg)
}

func verifyComponent(alg string, pub, msg, sig []byte) error {
	switch alg {
	case AlgEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return ErrInvalidSignature
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
			return ErrInvalidSignature
		}
		return nil

	case AlgMLDSA65:
		pk := &mldsa65.PublicKey{}
		if err := pk.UnmarshalBinary(pub); err != nil {
			return ErrInvalidSignature
		}
		if !mldsa65.Verify(pk, msg, nil, sig) {
			return ErrInvalidSignature
		}
		return nil
	}
	return ErrInvalidSignature
}
