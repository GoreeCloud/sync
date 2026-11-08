package deviceid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const rotationDomain = "GoreeCloud Sync device rotation v1\x00"
const maxRotationProofBytes = 4096

// RotationProof proves continuity between two distinct local device
// identities. It contains ONLY public keys and signatures, never secret seeds.
// Proofs are not certificate authorities or automatic trust instructions.
type RotationProof struct {
	Version      int    `json:"version"`
	Old          Public `json:"old"`
	New          Public `json:"new"`
	OldSignature string `json:"oldSignature"`
	NewSignature string `json:"newSignature"`
}

func rotationTranscript(old, next ed25519.PublicKey) []byte {
	msg := make([]byte, 0, len(rotationDomain)+2*ed25519.PublicKeySize)
	msg = append(msg, rotationDomain...)
	msg = append(msg, old...)
	msg = append(msg, next...)
	return msg
}

// MakeRotationProof does not modify either identity or trust store. To rotate
// safely, generate a second identity in a DIFFERENT private directory first.
func MakeRotationProof(old, next *Identity) (RotationProof, error) {
	if old == nil || next == nil {
		return RotationProof{}, errors.New("both old and new device identities are required")
	}
	oldPublic := old.secret.Public().(ed25519.PublicKey)
	newPublic := next.secret.Public().(ed25519.PublicKey)
	if bytes.Equal(oldPublic, newPublic) {
		return RotationProof{}, errors.New("replacement must use a different identity")
	}
	transcript := rotationTranscript(oldPublic, newPublic)
	proof := RotationProof{
		Version: 1,
		Old:     EncodePublic(oldPublic), New: EncodePublic(newPublic),
		OldSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(old.secret, transcript)),
		NewSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(next.secret, transcript)),
	}
	return proof, nil
}

// VerifyRotationProof requires the previously trusted public key supplied by
// the verifier. It must never trust the old key merely because it is embedded
// in the untrusted proof file.
func VerifyRotationProof(proof RotationProof, previouslyTrusted ed25519.PublicKey) (Public, error) {
	if len(previouslyTrusted) != ed25519.PublicKeySize || proof.Version != 1 {
		return Public{}, errors.New("missing trusted predecessor or unsupported rotation version")
	}
	old, err := ParsePublic(proof.Old.PublicKey)
	if err != nil {
		return Public{}, err
	}
	next, err := ParsePublic(proof.New.PublicKey)
	if err != nil {
		return Public{}, err
	}
	if proof.Old != EncodePublic(old) || proof.New != EncodePublic(next) ||
		subtle.ConstantTimeCompare(old, previouslyTrusted) != 1 || bytes.Equal(old, next) {
		return Public{}, errors.New("rotation predecessor is untrusted or identity fields are not canonical")
	}
	oldSignature, err1 := base64.RawURLEncoding.DecodeString(proof.OldSignature)
	newSignature, err2 := base64.RawURLEncoding.DecodeString(proof.NewSignature)
	if err1 != nil || err2 != nil || len(oldSignature) != ed25519.SignatureSize || len(newSignature) != ed25519.SignatureSize {
		return Public{}, errors.New("malformed signed rotation proof")
	}
	transcript := rotationTranscript(old, next)
	if !ed25519.Verify(old, transcript, oldSignature) || !ed25519.Verify(next, transcript, newSignature) {
		return Public{}, errors.New("rotation signatures did not verify")
	}
	return proof.New, nil
}

// ReadRotationProof only accepts a small regular file, refusing symbolic
// links. Rotation proof files are public, unlike the private identity store.
func ReadRotationProof(path string) (RotationProof, error) {
	var proof RotationProof
	st, err := os.Lstat(path)
	if err != nil {
		return proof, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxRotationProofBytes || st.Size() == 0 {
		return proof, errors.New("rotation proof must be a small regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return proof, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(st, actual) {
		return proof, errors.New("rotation proof file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRotationProofBytes+1))
	if err != nil || len(data) > maxRotationProofBytes {
		return proof, errors.New("rotation proof exceeds input limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return proof, fmt.Errorf("rotation proof invalid: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return RotationProof{}, errors.New("rotation proof contains trailing data")
	}
	return proof, nil
}

// VerifyPinnedRotation only checks the signatures against an existing trust
// pin; it has no side effects. Its result must not be auto-enrolled.
func VerifyPinnedRotation(root, oldFingerprint string, proof RotationProof) (Public, error) {
	old, err := Lookup(root, oldFingerprint)
	if err != nil {
		return Public{}, fmt.Errorf("old device identity is not already trusted: %w", err)
	}
	return VerifyRotationProof(proof, old)
}

// TrustRotation stages a second pin while preserving the old pin. In addition
// to cryptographic continuity, the caller must independently verify the new
// FULL fingerprint through a separate trusted channel. Existing pins are
// NEVER overwritten. Old revocation remains a separate explicit operation.
func TrustRotation(root, oldFingerprint string, proof RotationProof, independentlyVerifiedNewFingerprint string) (Public, error) {
	next, err := VerifyPinnedRotation(root, oldFingerprint, proof)
	if err != nil {
		return Public{}, err
	}
	if len(independentlyVerifiedNewFingerprint) != len(next.Fingerprint) ||
		subtle.ConstantTimeCompare([]byte(independentlyVerifiedNewFingerprint), []byte(next.Fingerprint)) != 1 {
		return Public{}, errors.New("independently verified new fingerprint does not match rotation proof")
	}
	return Trust(root, next.PublicKey, independentlyVerifiedNewFingerprint)
}
