package syncplan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPaddedConfidentialInventoryHidesExactLengths(t *testing.T) {
	_, remote, first, key, fp, peer, pinned := newConfidentialFixture(t)
	if _, err := ExportEncryptedChallengedOfflineInventory(remote, first, nil, peer, "", key); err != nil {
		t.Fatal(err)
	}
	// Adding a second small item changes the signed data length, but not its
	// 64 KiB encrypted size bucket.
	writeOfflineFile(t, remote, "another-file.txt", "additional content")
	second := filepath.Join(t.TempDir(), "encrypted-second.json")
	if _, err := ExportEncryptedChallengedOfflineInventory(remote, second, nil, peer, "", key); err != nil {
		t.Fatal(err)
	}
	var a, b confidentialOfflineInventory
	for _, pair := range []struct {
		path string
		into *confidentialOfflineInventory
	}{{first, &a}, {second, &b}} {
		data, err := os.ReadFile(pair.path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, pair.into); err != nil {
			t.Fatal(err)
		}
	}
	if a.Version != ConfidentialOfflineInventoryVersion || b.Version != ConfidentialOfflineInventoryVersion {
		t.Fatal("writer did not select padded v2")
	}
	if a.Nonce == b.Nonce || a.Ciphertext == b.Ciphertext {
		t.Fatal("identical nonce/ciphertext on distinct exports")
	}
	if len(a.Ciphertext) != len(b.Ciphertext) {
		t.Fatalf("similar inventories revealed exact size: %d vs %d", len(a.Ciphertext), len(b.Ciphertext))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(a.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if (len(decoded)-16)%confidentialInventoryPadBucket != 0 {
		t.Fatal("encrypted length not 64 KiB bucketed")
	}
	if _, err := ReadEncryptedOfflineInventory(first, fp, pinned, key); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEncryptedOfflineInventory(second, fp, pinned, key); err != nil {
		t.Fatal(err)
	}
	a.Version = confidentialInventoryLegacyVersion // version downgrade cannot reuse a v2 authentication tag.
	modified, _ := json.MarshalIndent(a, "", "  ")
	downgraded := filepath.Join(t.TempDir(), "downgraded.json")
	if err := os.WriteFile(downgraded, modified, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEncryptedOfflineInventory(downgraded, fp, pinned, key); err == nil {
		t.Fatal("version downgrade accepted")
	}
}

func TestLegacyConfidentialInventoryStillAuthenticates(t *testing.T) {
	_, remote, _, keyFile, fp, peer, pinned := newConfidentialFixture(t)
	_, signed, err := buildSignedOfflineInventory(remote, nil, peer, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signed)
	secret, err := readPrivateInventoryKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret[:])
	block, err := aes.NewCipher(secret[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, signed, []byte(confidentialInventoryAADV1))
	envelope := confidentialOfflineInventory{Version: confidentialInventoryLegacyVersion, Algorithm: confidentialInventoryAlgorithm, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext)}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEncryptedOfflineInventory(output, fp, pinned, keyFile); err != nil {
		t.Fatalf("legacy v1 denied: %v", err)
	}
	// Even an authenticated plaintext with a forged v2 length header fails.
	bad := make([]byte, confidentialInventoryPadBucket)
	binary.BigEndian.PutUint32(bad[:4], uint32(len(bad)))
	if _, err := rand.Read(bad[4:]); err != nil {
		t.Fatal(err)
	}
	ciphertext = aead.Seal(nil, nonce, bad, []byte(confidentialInventoryAADV2))
	envelope.Version = ConfidentialOfflineInventoryVersion
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	badData, _ := json.MarshalIndent(envelope, "", "  ")
	if bytes.Equal(badData, data) {
		t.Fatal("did not change test envelope")
	}
	badFile := filepath.Join(t.TempDir(), "bad-padding.json")
	if err := os.WriteFile(badFile, badData, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEncryptedOfflineInventory(badFile, fp, pinned, keyFile); err == nil {
		t.Fatal("accepted malformed authenticated length")
	}
}
