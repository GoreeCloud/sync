package syncplan

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

func newConfidentialFixture(t *testing.T) (local, remote, out, keyFile, fp string, peer *deviceid.Identity, pinned ed25519.PublicKey) {
	t.Helper()
	peer, _ = newOfflineIdentity(t)
	local, remote = t.TempDir(), t.TempDir()
	writeOfflineFile(t, local, "private-secret-filename.txt", "same")
	writeOfflineFile(t, remote, "private-secret-filename.txt", "same")
	out = filepath.Join(t.TempDir(), "encrypted.json")
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(keyDir, "exchange.key")
	if err := NewPrivateInventoryKeyFile(keyFile); err != nil {
		t.Fatal(err)
	}
	fp = peer.Public().Fingerprint
	var err error
	pinned, err = deviceid.ParsePublic(peer.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestConfidentialOfflineInventoryRoundTripAndDowngrades(t *testing.T) {
	local, remote, out, keyFile, fp, peer, pinned := newConfidentialFixture(t)
	challenge, err := NewOfflineInventoryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ExportEncryptedChallengedOfflineInventory(remote, out, nil, peer, challenge, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private-secret-filename")) || bytes.Contains(data, []byte("fingerprint")) || bytes.Contains(data, []byte("signature")) {
		t.Fatal("plaintext metadata leaked in encrypted envelope")
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("bad export permissions", err)
	}
	result, err := CompareVerifiedEncryptedOfflineInventory(local, nil, out, fp, pinned, challenge, keyFile)
	if err != nil || !result.ChallengeVerified || result.Plan.Identical != 1 {
		t.Fatalf("compare: %v %+v", err, result)
	}
	if _, err = ReadOfflineInventory(out, fp, pinned); err == nil {
		t.Fatal("encrypted envelope was accepted as plaintext")
	}
	if _, err = CompareVerifiedEncryptedOfflineInventory(local, nil, out, fp, pinned, "", keyFile); err == nil {
		t.Fatal("challenged envelope accepted without challenge")
	}
	wrongChallenge, err := NewOfflineInventoryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompareVerifiedEncryptedOfflineInventory(local, nil, out, fp, pinned, wrongChallenge, keyFile); err == nil {
		t.Fatal("wrong signed challenge accepted")
	}
	if _, err = ExportEncryptedChallengedOfflineInventory(remote, out, nil, peer, challenge, keyFile); err == nil {
		t.Fatal("overwrote existing inventory")
	}
	wrongKeyDir := t.TempDir()
	if err := os.Chmod(wrongKeyDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrongKey := filepath.Join(wrongKeyDir, "wrong.key")
	if err := NewPrivateInventoryKeyFile(wrongKey); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadEncryptedOfflineInventory(out, fp, pinned, wrongKey); err == nil {
		t.Fatal("wrong encryption key accepted")
	}
	if _, err = ReadEncryptedOfflineInventory(out, deviceid.Fingerprint(ed25519.PublicKey(make([]byte, 32))), pinned, keyFile); err == nil {
		t.Fatal("wrong pinned identity accepted")
	}
}

func TestConfidentialOfflineInventoryRejectsTampering(t *testing.T) {
	_, remote, out, keyFile, fp, peer, pinned := newConfidentialFixture(t)
	_, err := ExportEncryptedChallengedOfflineInventory(remote, out, nil, peer, "", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var obj confidentialOfflineInventory
	if err = json.Unmarshal(source, &obj); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*confidentialOfflineInventory){
		"wrong version":  func(v *confidentialOfflineInventory) { v.Version = 3 },
		"bad nonce":      func(v *confidentialOfflineInventory) { v.Nonce = "AAAA" },
		"bad ciphertext": func(v *confidentialOfflineInventory) { v.Ciphertext = "AAAA" },
		"different ciphertext": func(v *confidentialOfflineInventory) {
			if v.Ciphertext[0] == 'b' {
				v.Ciphertext = "a" + v.Ciphertext[1:]
			} else {
				v.Ciphertext = "b" + v.Ciphertext[1:]
			}
		},
		"unexpected algorithm": func(v *confidentialOfflineInventory) { v.Algorithm = "NO-SECURITY" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := obj
			mutate(&v)
			altered, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "tampered.json")
			if err = os.WriteFile(file, altered, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = ReadEncryptedOfflineInventory(file, fp, pinned, keyFile); err == nil {
				t.Fatal("tampered encrypted envelope accepted")
			}
		})
	}
	duplicate := bytes.Replace(source, []byte(`"version": 2`), []byte(`"version": 2, "version": 2`), 1)
	if bytes.Equal(source, duplicate) {
		t.Fatal("did not mutate")
	}
	file := filepath.Join(t.TempDir(), "duplicates.json")
	if err = os.WriteFile(file, duplicate, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadEncryptedOfflineInventory(file, fp, pinned, keyFile); err == nil {
		t.Fatal("duplicate JSON field accepted")
	}
	plain := filepath.Join(t.TempDir(), "plain.json")
	if _, err = ExportOfflineInventory(remote, plain, nil, peer); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadEncryptedOfflineInventory(plain, fp, pinned, keyFile); err == nil {
		t.Fatal("plaintext downgraded into encrypted reader")
	}
}

func TestInventoryKeyFileGuards(t *testing.T) {
	local, remote, _, key, _, peer, _ := newConfidentialFixture(t)
	if err := NewPrivateInventoryKeyFile(key); err == nil {
		t.Fatal("key overwritten")
	}
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("key mode incorrect", err)
	}
	if _, err := ExportEncryptedChallengedOfflineInventory(remote, filepath.Join(t.TempDir(), "private.json"), nil, peer, "", filepath.Join(remote, "key")); err == nil {
		t.Fatal("key inside scan root accepted")
	}
	link := filepath.Join(filepath.Dir(key), "symlink.key")
	if err := os.Symlink(key, link); err == nil {
		if _, err = readPrivateInventoryKey(link); err == nil {
			t.Fatal("symlinked key accepted")
		}
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateInventoryKey(key); err == nil {
		t.Fatal("permissive key accepted")
	}
	// No copied contents on a failed export.
	out := filepath.Join(t.TempDir(), "result.json")
	if _, err := ExportEncryptedChallengedOfflineInventory(local, out, nil, peer, "", key); err == nil {
		t.Fatal("insecure key export accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("export was written")
	}
}

func TestConfidentialOneUseTicketNotSpentOnWrongKey(t *testing.T) {
	local, remote, out, keyFile, fp, peer, pinned := newConfidentialFixture(t)
	tickets := t.TempDir()
	if err := os.Chmod(tickets, 0700); err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(tickets, "ticket.json")
	challenge, err := IssueOneUseInventoryChallenge(ticket, local, fp, nil, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ExportEncryptedChallengedOfflineInventory(remote, out, nil, peer, challenge, keyFile); err != nil {
		t.Fatal(err)
	}
	wrongDir := t.TempDir()
	if err := os.Chmod(wrongDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(wrongDir, "wrong.key")
	if err := NewPrivateInventoryKeyFile(wrong); err != nil {
		t.Fatal(err)
	}
	if _, err = CompareWithEncryptedOneUseInventoryTicket(local, nil, out, fp, pinned, ticket, wrong); err == nil {
		t.Fatal("wrong key consumed")
	}
	if _, err = os.Lstat(ticket + ".used"); !os.IsNotExist(err) {
		t.Fatal("bad comparison spent ticket")
	}
	result, err := CompareWithEncryptedOneUseInventoryTicket(local, nil, out, fp, pinned, ticket, keyFile)
	if err != nil || !result.OneUseChallengeConsumed {
		t.Fatalf("good compare: %v %+v", err, result)
	}
	if _, err = CompareWithEncryptedOneUseInventoryTicket(local, nil, out, fp, pinned, ticket, keyFile); err == nil {
		t.Fatal("replay succeeded")
	}
	if _, err = os.Lstat(ticket + ".used"); err != nil {
		t.Fatal("used marker missing", err)
	}
	if strings.Contains(out, "private-secret-filename.txt") {
		t.Fatal("test error")
	}
}
