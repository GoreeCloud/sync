package deviceid

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestOfflineInventorySignatureDomainAndTamper(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	if _, err := Initialize(root); err != nil {
		t.Fatal(err)
	}
	own, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublic(own.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(`{"version":1,"fingerprint":"test"}`)
	sig := own.SignOfflineInventory(first)
	if len(sig) != ed25519.SignatureSize || !VerifyOfflineInventory(pub, first, sig) {
		t.Fatal("valid signature failed")
	}
	if VerifyOfflineInventory(pub, []byte(`{"version":2,"fingerprint":"test"}`), sig) {
		t.Fatal("modified payload verified")
	}
	if VerifyOfflineInventory(pub, first, []byte("wrong")) {
		t.Fatal("invalid signature accepted")
	}
	if ed25519.Verify(pub, first, sig) {
		t.Fatal("signature not domain-separated")
	}
}
