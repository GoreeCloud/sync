package deviceid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tDir(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "identity") }
func TestInitializeLoadNoOverwrite(t *testing.T) {
	root := tDir(t)
	pub, err := Initialize(root)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Algorithm != "Ed25519" || len(pub.Fingerprint) != 71 || len(pub.PublicKey) != 43 {
		t.Fatalf("unexpected identity %v", pub)
	}
	id, err := Load(root)
	if err != nil || id.Public() != pub {
		t.Fatalf("identity round-trip %v %v", id, err)
	}
	if _, err := Initialize(root); !errors.Is(err, os.ErrExist) {
		t.Fatalf("identity unexpectedly replaced: %v", err)
	}
	if got, err := Load(root); err != nil || got.Public() != pub {
		t.Fatal("identity modified on failed create")
	}
	if st, err := os.Stat(filepath.Join(root, identityName)); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("private key not 0600: %v %v", st, err)
	}
	if st, err := os.Stat(root); err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("identity root not 0700: %v %v", st, err)
	}
}
func TestRejectUnsafeIdentityStore(t *testing.T) {
	root := tDir(t)
	pub, err := Initialize(root)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, identityName)
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted world-readable identity")
	}
	os.Chmod(p, 0600)
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted world-accessible key directory")
	}
	os.Chmod(root, 0700)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "not-a-key"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted symlink identity")
	}
	os.Remove(p)
	if err := os.WriteFile(p, []byte(`{"version":1,"seed":"bad","public":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted corrupted identity")
	}
	_ = pub
}
func TestTrustRequiresIndependentFingerprint(t *testing.T) {
	a := tDir(t)
	b := tDir(t)
	aPub, err := Initialize(a)
	if err != nil {
		t.Fatal(err)
	}
	bPub, err := Initialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(a, bPub.PublicKey, aPub.Fingerprint); err == nil {
		t.Fatal("accepted incorrect fingerprint")
	}
	if _, err := Trust(a, aPub.PublicKey, aPub.Fingerprint); err == nil {
		t.Fatal("accepted self identity")
	}
	if _, err := Trust(a, bPub.PublicKey, bPub.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(a, bPub.PublicKey, bPub.Fingerprint); !errors.Is(err, os.ErrExist) {
		t.Fatalf("duplicate trust was overwritten: %v", err)
	}
	stored, err := Lookup(a, bPub.Fingerprint)
	if err != nil || EncodePublic(stored) != bPub {
		t.Fatalf("trust lookup: %v", err)
	}
	list, err := List(a)
	if err != nil || len(list) != 1 || list[0] != bPub {
		t.Fatalf("trust list: %+v %v", list, err)
	}
	if _, err := Lookup(a, strings.ToUpper(bPub.Fingerprint)); err == nil {
		t.Fatal("accepted noncanonical fingerprint")
	}
	if _, err := Lookup(a, "sha256:../path"); err == nil {
		t.Fatal("accepted path traversal")
	}
	if _, err := Trust(a, base64.RawURLEncoding.EncodeToString([]byte("short")), bPub.Fingerprint); err == nil {
		t.Fatal("accepted short public key")
	}
}
func TestAlteredTrustRecordRejected(t *testing.T) {
	a, b := tDir(t), tDir(t)
	Initialize(a)
	pub, _ := Initialize(b)
	if _, err := Trust(a, pub.PublicKey, pub.Fingerprint); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a, "trusted", strings.TrimPrefix(pub.Fingerprint, "sha256:")+".json")
	if err := os.WriteFile(path, []byte(`{"algorithm":"Ed25519","publicKey":"junk","fingerprint":"`+pub.Fingerprint+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(a, pub.Fingerprint); err == nil {
		t.Fatal("accepted corrupted trust record")
	}
	if _, err := List(a); err == nil {
		t.Fatal("list accepted corrupted trust record")
	}
}
func TestProofNonceSessionBinding(t *testing.T) {
	root := tDir(t)
	Initialize(root)
	id, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublic(id.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var challenge, second [32]byte
	rand.Read(challenge[:])
	rand.Read(second[:])
	if challenge == second {
		t.Fatal("randomness failure")
	}
	var key, wrong [32]byte
	rand.Read(key[:])
	rand.Read(wrong[:])
	if key == wrong {
		t.Fatal("randomness failure")
	}
	sig := id.SignReceiverProof(challenge, key)
	if !VerifyReceiverProof(pub, challenge, key, sig) {
		t.Fatal("real proof rejected")
	}
	if VerifyReceiverProof(pub, second, key, sig) {
		t.Fatal("replayed nonce accepted")
	}
	if VerifyReceiverProof(pub, challenge, wrong, sig) {
		t.Fatal("wrong transfer key accepted")
	}
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyReceiverProof(wrongPub, challenge, key, sig) {
		t.Fatal("wrong trusted identity accepted")
	}
	sig[0] ^= 0x80
	if VerifyReceiverProof(pub, challenge, key, sig) {
		t.Fatal("tampered signature accepted")
	}
}

func TestUntrustOnlyPinnedIdentity(t *testing.T) {
	a, b := tDir(t), tDir(t)
	Initialize(a)
	peer, _ := Initialize(b)
	if err := Untrust(a, peer.Fingerprint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected untrusted removal: %v", err)
	}
	if _, err := Trust(a, peer.PublicKey, peer.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := Untrust(a, "sha256:../invalid"); err == nil {
		t.Fatal("accepted traversal")
	}
	if err := Untrust(a, peer.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(a, peer.Fingerprint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust remains: %v", err)
	}
	empty, err := List(a)
	if err != nil || len(empty) != 0 {
		t.Fatalf("expected no pinned peers: %+v %v", empty, err)
	}
}
func TestSenderProofBindsTicketAndCiphertext(t *testing.T) {
	root := tDir(t)
	Initialize(root)
	id, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ParsePublic(id.Public().PublicKey)
	var secret, wrong [32]byte
	rand.Read(secret[:])
	rand.Read(wrong[:])
	ticket := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	reqMAC := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	sig := id.SignSenderProof(ticket, secret, reqMAC)
	if !VerifySenderProof(pub, ticket, secret, reqMAC, sig) {
		t.Fatal("valid sender proof rejected")
	}
	if VerifySenderProof(pub, ticket, wrong, reqMAC, sig) {
		t.Fatal("sender proof accepted wrong pairing key")
	}
	if VerifySenderProof(pub, ticket, secret, base64.RawURLEncoding.EncodeToString(make([]byte, 31)), sig) {
		t.Fatal("sender proof accepted wrong request MAC")
	}
	changed := []byte(ticket)
	changed[0] = 'X'
	if VerifySenderProof(pub, string(changed), secret, reqMAC, sig) {
		t.Fatal("sender proof accepted a different receiver ticket")
	}
}
