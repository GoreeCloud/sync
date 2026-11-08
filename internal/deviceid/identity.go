// Package deviceid provides explicit, local Ed25519 device identities and
// pinned trust records. It is not a PKI or an automatic pairing mechanism.
package deviceid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const identityName = "identity.json"
const recordLimit = 2048
const proofDomain = "GoreeCloud Sync receiver proof v1\x00"

type Public struct {
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
}
type Identity struct{ secret ed25519.PrivateKey }
type identityDisk struct {
	Version int    `json:"version"`
	Seed    string `json:"seed"`
	Public  Public `json:"public"`
}

func Fingerprint(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(digest[:])
}
func EncodePublic(key ed25519.PublicKey) Public {
	return Public{Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key), Fingerprint: Fingerprint(key)}
}
func ParsePublic(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be base64url Ed25519 public key (32 bytes)")
	}
	return ed25519.PublicKey(raw), nil
}

// Private identity and trusted-peer records use platform-specific protected
// filesystem primitives. Linux/Android anchor every path component to opened
// directory descriptors; other systems retain a documented weaker fallback.
func checkPrivateDir(dir string) error        { return verifyDevicePrivateDir(dir) }
func ensurePrivateDir(dir string) error       { return ensureDevicePrivateDir(dir) }
func privateFile(path string) ([]byte, error) { return readDevicePrivateFile(path, recordLimit) }
func createPrivateFile(dir, name string, content []byte) error {
	return writeDevicePrivateFile(dir, name, content)
}
func (i *Identity) Public() Public { return EncodePublic(i.secret.Public().(ed25519.PublicKey)) }
func Initialize(root string) (Public, error) {
	if err := ensurePrivateDir(root); err != nil {
		return Public{}, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Public{}, err
	}
	ident := &Identity{secret: priv}
	record := identityDisk{Version: 1, Seed: base64.RawURLEncoding.EncodeToString(priv.Seed()), Public: ident.Public()}
	encoded, err := json.Marshal(record)
	if err != nil {
		return Public{}, err
	}
	if err := createPrivateFile(root, identityName, encoded); err != nil {
		return Public{}, err
	}
	return record.Public, nil
}
func Load(root string) (*Identity, error) {
	if err := checkPrivateDir(root); err != nil {
		return nil, err
	}
	content, err := privateFile(filepath.Join(root, identityName))
	if err != nil {
		return nil, err
	}
	var rec identityDisk
	if err = json.Unmarshal(content, &rec); err != nil {
		return nil, fmt.Errorf("invalid identity file: %w", err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(rec.Seed)
	if err != nil || rec.Version != 1 || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid identity record version or seed")
	}
	id := &Identity{secret: ed25519.NewKeyFromSeed(seed)}
	got := id.Public()
	if rec.Public != got {
		return nil, errors.New("identity public key does not match private seed")
	}
	return id, nil
}

// Trust pins a device only when the caller separately supplies its complete
// 256-bit SHA-256 public-key fingerprint. Never infer the expected fingerprint
// from the untrusted public-key text during this operation.
func Trust(root, publicKey, verifiedFingerprint string) (Public, error) {
	if err := checkPrivateDir(root); err != nil {
		return Public{}, err
	}
	if _, err := Load(root); err != nil {
		return Public{}, err
	}
	pub, err := ParsePublic(publicKey)
	if err != nil {
		return Public{}, err
	}
	rec := EncodePublic(pub)
	if len(verifiedFingerprint) != len(rec.Fingerprint) || subtle.ConstantTimeCompare([]byte(verifiedFingerprint), []byte(rec.Fingerprint)) != 1 {
		return Public{}, errors.New("independently verified fingerprint does not match peer public key")
	}
	own, err := Load(root)
	if err != nil {
		return Public{}, err
	}
	if rec.Fingerprint == own.Public().Fingerprint {
		return Public{}, errors.New("refusing to trust own identity as a peer")
	}
	dir := filepath.Join(root, "trusted")
	if err := ensurePrivateDir(dir); err != nil {
		return Public{}, err
	}
	record, err := json.Marshal(rec)
	if err != nil {
		return Public{}, err
	}
	if err := createPrivateFile(dir, strings.TrimPrefix(rec.Fingerprint, "sha256:")+".json", record); err != nil {
		return Public{}, err
	}
	return rec, nil
}
func validFingerprint(fp string) bool {
	if !strings.HasPrefix(fp, "sha256:") || len(fp) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(fp, "sha256:"))
	return err == nil && fp == strings.ToLower(fp)
}
func Lookup(root, fp string) (ed25519.PublicKey, error) {
	if !validFingerprint(fp) {
		return nil, errors.New("invalid full SHA-256 fingerprint")
	}
	dir := filepath.Join(root, "trusted")
	if err := checkPrivateDir(root); err != nil {
		return nil, err
	}
	if err := checkPrivateDir(dir); err != nil {
		return nil, err
	}
	b, err := privateFile(filepath.Join(dir, strings.TrimPrefix(fp, "sha256:")+".json"))
	if err != nil {
		return nil, err
	}
	var rec Public
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	pub, err := ParsePublic(rec.PublicKey)
	if err != nil {
		return nil, err
	}
	canonical := EncodePublic(pub)
	if rec != canonical || rec.Fingerprint != fp {
		return nil, errors.New("invalid or altered trust record")
	}
	return pub, nil
}
func List(root string) ([]Public, error) {
	if err := checkPrivateDir(root); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "trusted")
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return []Public{}, nil
	} else if err != nil {
		return nil, err
	}
	entries, err := listDevicePrivateFileNames(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Public, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasSuffix(entry, ".json") {
			return nil, errors.New("unexpected entry in trust directory")
		}
		fp := "sha256:" + strings.TrimSuffix(entry, ".json")
		key, err := Lookup(root, fp)
		if err != nil {
			return nil, err
		}
		out = append(out, EncodePublic(key))
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Fingerprint < out[b].Fingerprint })
	return out, nil
}
func transcript(challenge [32]byte, pairingKey [32]byte) []byte {
	// The proof binds this exact one-time receiver key to an unpredictable
	// challenge without disclosing the key over the network.
	keyHash := sha256.Sum256(pairingKey[:])
	msg := make([]byte, 0, len(proofDomain)+64)
	msg = append(msg, proofDomain...)
	msg = append(msg, challenge[:]...)
	msg = append(msg, keyHash[:]...)
	return msg
}
func (i *Identity) SignReceiverProof(challenge [32]byte, pairingKey [32]byte) []byte {
	return ed25519.Sign(i.secret, transcript(challenge, pairingKey))
}
func VerifyReceiverProof(public ed25519.PublicKey, challenge [32]byte, pairingKey [32]byte, signature []byte) bool {
	return len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(public, transcript(challenge, pairingKey), signature)
}

// Untrust explicitly removes an existing pinned peer. This prevents future
// pinned transfers to that peer but does not revoke an already used pairing key.
func Untrust(root, fingerprint string) error {
	if _, err := Lookup(root, fingerprint); err != nil {
		return err
	}
	dir := filepath.Join(root, "trusted")
	return removeDevicePrivateFile(dir, strings.TrimPrefix(fingerprint, "sha256:")+".json")
}

const senderProofDomain = "GoreeCloud Sync sender upload proof v1\x00"

// senderTranscript ties a sender identity to the exact one-time receiver
// session, a receiver-issued ticket, and the authenticated ciphertext request.
func senderTranscript(ticket string, pairingKey [32]byte, requestMAC string) []byte {
	keyHash := sha256.Sum256(pairingKey[:])
	// Request MAC is the fixed-size base64url representation of a 256-bit HMAC.
	// The ticket is a fixed-size base64url MAC-protected receiver nonce.
	msg := make([]byte, 0, len(senderProofDomain)+32+len(ticket)+len(requestMAC))
	msg = append(msg, senderProofDomain...)
	msg = append(msg, keyHash[:]...)
	msg = append(msg, ticket...)
	msg = append(msg, requestMAC...)
	return msg
}
func (i *Identity) SignSenderProof(ticket string, pairingKey [32]byte, requestMAC string) []byte {
	return ed25519.Sign(i.secret, senderTranscript(ticket, pairingKey, requestMAC))
}
func VerifySenderProof(pub ed25519.PublicKey, ticket string, pairingKey [32]byte, requestMAC string, signature []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize &&
		len(ticket) == 86 && len(requestMAC) == 43 && ed25519.Verify(pub, senderTranscript(ticket, pairingKey, requestMAC), signature)
}

const offlineInventoryDomain = "GoreeCloud Sync signed offline inventory v1\x00"

// SignOfflineInventory signs a domain-separated digest of a canonical inventory
// payload. The signature proves authorship, not the age or accuracy of a scan.
func (i *Identity) SignOfflineInventory(payload []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(offlineInventoryDomain))
	_, _ = h.Write(payload)
	return ed25519.Sign(i.secret, h.Sum(nil))
}

// VerifyOfflineInventory never accepts an unsigned or differently scoped blob.
func VerifyOfflineInventory(pub ed25519.PublicKey, payload, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	h := sha256.New()
	_, _ = h.Write([]byte(offlineInventoryDomain))
	_, _ = h.Write(payload)
	return ed25519.Verify(pub, h.Sum(nil), signature)
}
