package stepauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func testKeyset(t *testing.T) *SigningKeyset {
	t.Helper()
	ks, err := GenerateKeyset("ks_test")
	if err != nil {
		t.Fatalf("generating keyset: %v", err)
	}
	return ks
}

func reEncode(t *testing.T, envelopeJSON []byte, fn func(*Envelope)) []byte {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		t.Fatalf("unmarshaling envelope: %v", err)
	}
	fn(&env)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}
	return out
}

func TestSigningKeysetStringRedactsPrivateKeys(t *testing.T) {
	ks := testKeyset(t)

	out := fmt.Sprintf("%+v keys:%+v", ks, ks.Keys)

	for _, k := range ks.Keys {
		if strings.Contains(out, fmt.Sprintf("%v", k.Priv)) {
			t.Errorf("formatted output contains raw private key bytes: %s", out)
		}
	}
	if !strings.Contains(out, "REDACTED") {
		t.Errorf("formatted output does not redact private key material: %s", out)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	ks := testKeyset(t)
	payload := []byte(`{"requestId":"req_1","senderId":"sp.example.com"}`)

	envelopeJSON, err := SignEnvelope(ks, payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	got, err := VerifyEnvelope(envelopeJSON, []Keyset{ks.PublicKeyset()})
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload round-tripped as %q, want %q", got, payload)
	}
}

// TestKeysetCarriesBothAlgorithms guards the hybrid pair itself: dropping a
// component would leave signatures verifying against one primitive alone.
func TestKeysetCarriesBothAlgorithms(t *testing.T) {
	ks := testKeyset(t)
	wantAlgs := []string{AlgEd25519, AlgMLDSA65}

	if len(ks.Keys) != len(wantAlgs) {
		t.Fatalf("keyset has %d components, want %d", len(ks.Keys), len(wantAlgs))
	}
	for i, alg := range wantAlgs {
		if ks.Keys[i].Alg != alg {
			t.Errorf("component %d is %q, want %q", i, ks.Keys[i].Alg, alg)
		}
		if ks.Keys[i].Idx != i {
			t.Errorf("component %d carries idx %d", i, ks.Keys[i].Idx)
		}
	}
}

// TestSeedDerivationIsDeterministic checks that one seed always expands to
// the same public key.
func TestSeedDerivationIsDeterministic(t *testing.T) {
	seeds := map[string][]byte{
		AlgEd25519: bytes.Repeat([]byte{0x01}, ed25519.SeedSize),
		AlgMLDSA65: bytes.Repeat([]byte{0x02}, mldsa65.SeedSize),
	}

	for alg, seed := range seeds {
		t.Run(alg, func(t *testing.T) {
			first, err := KeyFromSeed(alg, seed)
			if err != nil {
				t.Fatalf("expanding seed: %v", err)
			}
			second, err := KeyFromSeed(alg, seed)
			if err != nil {
				t.Fatalf("expanding seed again: %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Error("one seed expanded to two different public keys")
			}
			if len(first) == 0 {
				t.Error("seed expanded to an empty public key")
			}
		})
	}
}

// TestKeysetJSONIsBackwardCompatible pins the persisted shape. ML-DSA private
// keys cannot be reduced back to a seed, so a field rename here would strand
// every existing keyset with no migration path short of re-registering with
// the hub.
func TestKeysetJSONIsBackwardCompatible(t *testing.T) {
	raw, err := json.Marshal(testKeyset(t))
	if err != nil {
		t.Fatalf("marshaling keyset: %v", err)
	}

	var shape struct {
		KeysetID string `json:"keysetId"`
		Keys     []struct {
			Idx  int    `json:"idx"`
			Alg  string `json:"alg"`
			Pub  string `json:"pub"`
			Priv string `json:"priv"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("keyset JSON does not match the persisted shape: %v", err)
	}

	if shape.KeysetID == "" || len(shape.Keys) != len(KeysetAlgs()) {
		t.Fatalf("unexpected keyset shape: %s", raw)
	}
	for i, k := range shape.Keys {
		if k.Alg != KeysetAlgs()[i] || k.Idx != i || k.Pub == "" || k.Priv == "" {
			t.Errorf("component %d did not round-trip: %+v", i, k)
		}
	}

	// A stored keyset must come back able to sign.
	var restored SigningKeyset
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("restoring keyset: %v", err)
	}
	envelopeJSON, err := SignEnvelope(&restored, []byte(`{"requestId":"req_1"}`))
	if err != nil {
		t.Fatalf("signing with a restored keyset: %v", err)
	}
	if _, err := VerifyEnvelope(envelopeJSON, []Keyset{restored.PublicKeyset()}); err != nil {
		t.Errorf("envelope from a restored keyset did not verify: %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	ks := testKeyset(t)
	envelopeJSON, err := SignEnvelope(ks, []byte(`{"requestId":"req_1"}`))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	tampered := reEncode(t, envelopeJSON, func(env *Envelope) {
		env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"requestId":"req_2"}`))
	})

	if _, err := VerifyEnvelope(tampered, []Keyset{ks.PublicKeyset()}); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("tampered payload verified, err = %v", err)
	}
}

func TestVerifyRejectsUnknownKeyset(t *testing.T) {
	ks := testKeyset(t)
	envelopeJSON, err := SignEnvelope(ks, []byte(`{}`))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	other := ks.PublicKeyset()
	other.KeysetID = "ks_someone_else"

	if _, err := VerifyEnvelope(envelopeJSON, []Keyset{other}); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("envelope verified against an unresolvable keysetId, err = %v", err)
	}
}

// TestVerifyRejectsZeroKeyKeyset covers the vacuous all-of: with no components
// every check passes trivially and any payload verifies.
func TestVerifyRejectsZeroKeyKeyset(t *testing.T) {
	// Built directly, not via SignEnvelope: a zero-signature envelope keeps
	// the signature-count check (0 == 0) from rejecting first, so only the
	// zero-key guard can catch it.
	envelopeJSON, err := json.Marshal(Envelope{
		Payload:   base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Signature: Signature{KeysetID: "ks_test", Signatures: []string{}},
	})
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}

	empty := Keyset{KeysetID: "ks_test"}
	if _, err := VerifyEnvelope(envelopeJSON, []Keyset{empty}); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("zero-key keyset verified an envelope, err = %v", err)
	}
}

func TestVerifyRejectsSignatureCountMismatch(t *testing.T) {
	ks := testKeyset(t)
	envelopeJSON, err := SignEnvelope(ks, []byte(`{}`))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	for name, mutate := range map[string]func(*Envelope){
		"too few":  func(env *Envelope) { env.Signature.Signatures = env.Signature.Signatures[:1] },
		"too many": func(env *Envelope) { env.Signature.Signatures = append(env.Signature.Signatures, "AA==") },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := reEncode(t, envelopeJSON, mutate)
			if _, err := VerifyEnvelope(mutated, []Keyset{ks.PublicKeyset()}); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("%s signatures verified, err = %v", name, err)
			}
		})
	}
}

// TestVerifyRejectsSingleBadComponent is the hybrid downgrade check. An
// implementation that stops at the first valid signature, or only checks the
// classical half, passes every other test in this file and fails this one.
func TestVerifyRejectsSingleBadComponent(t *testing.T) {
	ks := testKeyset(t)
	payload := []byte(`{"requestId":"req_1"}`)

	envelopeJSON, err := SignEnvelope(ks, payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// A signature valid for other bytes: structurally sound, wrong message.
	decoy, err := SignEnvelope(ks, []byte(`{"requestId":"req_other"}`))
	if err != nil {
		t.Fatalf("signing decoy: %v", err)
	}
	var decoyEnv Envelope
	if err := json.Unmarshal(decoy, &decoyEnv); err != nil {
		t.Fatalf("unmarshaling decoy: %v", err)
	}

	for idx, alg := range KeysetAlgs() {
		t.Run(alg, func(t *testing.T) {
			swapped := reEncode(t, envelopeJSON, func(env *Envelope) {
				env.Signature.Signatures[idx] = decoyEnv.Signature.Signatures[idx]
			})
			if _, err := VerifyEnvelope(swapped, []Keyset{ks.PublicKeyset()}); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("envelope verified with only the %s component wrong, err = %v", alg, err)
			}
		})
	}
}

func TestSignRejectsDuplicateAlgKeyset(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ks := &SigningKeyset{
		KeysetID: "ks_test",
		Keys: []SigningKey{
			{Idx: 0, Alg: AlgEd25519, Pub: pub1, Priv: priv1},
			{Idx: 1, Alg: AlgEd25519, Pub: pub2, Priv: priv2},
		},
	}

	if _, err := SignEnvelope(ks, []byte(`{}`)); err == nil {
		t.Error("signing with a duplicate-algorithm keyset succeeded")
	}
}

func TestVerifyRejectsDuplicateAlgKeyset(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyset := Keyset{
		KeysetID: "ks_test",
		Keys: []KeysetKey{
			{Idx: 0, Alg: AlgEd25519, Pub: base64.StdEncoding.EncodeToString(pub1)},
			{Idx: 1, Alg: AlgEd25519, Pub: base64.StdEncoding.EncodeToString(pub2)},
		},
	}
	envelopeJSON, err := json.Marshal(Envelope{
		Payload:   base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Signature: Signature{KeysetID: "ks_test", Signatures: []string{"AA==", "AA=="}},
	})
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}

	if _, err := VerifyEnvelope(envelopeJSON, []Keyset{keyset}); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("duplicate-algorithm keyset verified an envelope, err = %v", err)
	}
}

// TestEnvelopeWireEncoding pins the two things a language port can silently
// get wrong: the base64 alphabet and the JSON key names. Both are invisible
// to a test that signs and verifies with the same code.
func TestEnvelopeWireEncoding(t *testing.T) {
	ks, err := GenerateKeyset("ks_wire")
	if err != nil {
		t.Fatalf("generating keyset: %v", err)
	}

	// Encodes to "/++++Q==" in the standard alphabet and "_----Q==" in
	// base64url, so the two are distinguishable here where short ASCII
	// payloads make them identical.
	payload := []byte{0xff, 0xef, 0xbe, 0xfb, 0xff, 0x41}
	wantPayload := base64.StdEncoding.EncodeToString(payload)

	envelopeBytes, err := SignEnvelope(ks, payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(envelopeBytes, &raw); err != nil {
		t.Fatalf("unmarshaling envelope: %v", err)
	}
	if _, ok := raw["payload"]; !ok {
		t.Error(`envelope has no "payload" key`)
	}
	if _, ok := raw["signature"]; !ok {
		t.Error(`envelope has no "signature" key`)
	}

	var got struct {
		Payload   string `json:"payload"`
		Signature struct {
			KeysetID   string   `json:"keysetId"`
			Signatures []string `json:"signatures"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(envelopeBytes, &got); err != nil {
		t.Fatalf("unmarshaling envelope: %v", err)
	}
	if got.Payload != wantPayload {
		t.Errorf("payload encoding = %q, want %q (standard alphabet)", got.Payload, wantPayload)
	}
	if got.Signature.KeysetID != "ks_wire" {
		t.Errorf(`signature.keysetId = %q, want "ks_wire"`, got.Signature.KeysetID)
	}
	if len(got.Signature.Signatures) != len(KeysetAlgs()) {
		t.Errorf("signature.signatures = %d entries, want %d", len(got.Signature.Signatures), len(KeysetAlgs()))
	}
}

func TestDecodePayloadDoesNotVerify(t *testing.T) {
	ks := testKeyset(t)
	envelopeJSON, err := SignEnvelope(ks, []byte(`{"requestId":"req_1"}`))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	tampered := reEncode(t, envelopeJSON, func(env *Envelope) {
		env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"requestId":"forged"}`))
	})

	// Routing needs the payload before the keyset is known, so this must decode
	// what VerifyEnvelope would reject.
	got, err := DecodeEnvelopePayload(tampered)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if string(got) != `{"requestId":"forged"}` {
		t.Errorf("decoded %q", got)
	}
}
