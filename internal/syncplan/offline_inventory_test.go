package syncplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

func newOfflineIdentity(t *testing.T) (*deviceid.Identity, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "id")
	if _, err := deviceid.Initialize(dir); err != nil {
		t.Fatal(err)
	}
	id, err := deviceid.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id, dir
}

func writeOfflineFile(t *testing.T, dir, filename, contents string) {
	t.Helper()
	p := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSignedOfflineInventoryComparison(t *testing.T) {
	peer, _ := newOfflineIdentity(t)
	localID, localStore := newOfflineIdentity(t)
	_ = localID
	trusted, err := deviceid.Trust(localStore, peer.Public().PublicKey, peer.Public().Fingerprint)
	if err != nil || trusted.Fingerprint != peer.Public().Fingerprint {
		t.Fatal(err)
	}
	root := t.TempDir()
	local := t.TempDir()
	writeOfflineFile(t, root, "common", "same")
	writeOfflineFile(t, root, "remote", "only remote")
	writeOfflineFile(t, root, "changed", "REMOTE")
	writeOfflineFile(t, root, "ignored.tmp", "unshared metadata")
	writeOfflineFile(t, local, "common", "same")
	writeOfflineFile(t, local, "local", "only local")
	writeOfflineFile(t, local, "changed", "LOCAL!")
	writeOfflineFile(t, local, "ignored.tmp", "something else")
	export := filepath.Join(t.TempDir(), "peer.json")
	bundle, err := ExportOfflineInventory(root, export, []string{"*.tmp"}, peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Files) != 3 {
		t.Fatalf("expected 3 filtered files; got %d", len(bundle.Files))
	}
	st, err := os.Stat(export)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("private export permissions: %v / %v", st, err)
	}
	if _, err := ExportOfflineInventory(root, export, []string{"*.tmp"}, peer); err == nil {
		t.Fatal("overwrote signed inventory")
	}
	pinned, err := deviceid.Lookup(localStore, peer.Public().Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadOfflineInventory(export, peer.Public().Fingerprint, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if read.Signature != bundle.Signature {
		t.Fatal("signature changed")
	}
	comparison, err := CompareVerifiedOfflineInventory(local, []string{"*.tmp"}, export, peer.Public().Fingerprint, pinned)
	if err != nil {
		t.Fatal(err)
	}
	p := comparison.Plan
	if !p.ReadOnly || p.Identical != 1 || p.SourceOnly != 1 || p.TargetOnly != 1 || p.Different != 1 || len(p.Changes) != 4 {
		t.Fatalf("unexpected comparison: %+v", p)
	}
	if p.Changes[0].Path != "changed" || p.Changes[1].Path != "common" || p.Changes[2].Path != "local" || p.Changes[3].Path != "remote" {
		t.Fatalf("not sorted: %+v", p.Changes)
	}
	if _, err := CompareVerifiedOfflineInventory(local, nil, export, peer.Public().Fingerprint, pinned); err == nil {
		t.Fatal("accepted mismatched excludes")
	}
	if _, err := ReadOfflineInventory(export, localID.Public().Fingerprint, mustPub(t, localID.Public().PublicKey)); err == nil {
		t.Fatal("accepted wrong pinned peer")
	}
}

func TestSignedOfflineInventoryTamperAndRejectPaths(t *testing.T) {
	peer, _ := newOfflineIdentity(t)
	root := t.TempDir()
	writeOfflineFile(t, root, "file.txt", "safe")
	export := filepath.Join(t.TempDir(), "inventory.json")
	if _, err := ExportOfflineInventory(root, export, nil, peer); err != nil {
		t.Fatal(err)
	}
	pinned, err := deviceid.ParsePublic(peer.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(export)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		modify func([]byte) []byte
	}{
		{"changed hash", func(raw []byte) []byte { return bytes.Replace(raw, []byte("\"size\": 4"), []byte("\"size\": 5"), 1) }},
		{"trailing json", func(raw []byte) []byte { return append(append([]byte(nil), raw...), []byte("{}")...) }},
		{"unknown field", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte("\"version\": 1,"), []byte("\"version\": 1, \"evil\": true,"), 1)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bad := filepath.Join(t.TempDir(), "altered.json")
			mutated := tt.modify(original)
			if bytes.Equal(mutated, original) {
				t.Fatal("test failed to mutate")
			}
			if err := os.WriteFile(bad, mutated, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadOfflineInventory(bad, peer.Public().Fingerprint, pinned); err == nil {
				t.Fatal("tampered inventory accepted")
			}
		})
	}
	if _, err := ExportOfflineInventory(root, filepath.Join(root, "self.json"), nil, peer); err == nil {
		t.Fatal("export inside scan root accepted")
	}
	if _, err := os.Lstat(filepath.Join(root, "self.json")); err == nil {
		t.Fatal("forbidden file created")
	}
	link := filepath.Join(t.TempDir(), "linked.json")
	if err := os.Symlink(export, link); err == nil {
		if _, err := ReadOfflineInventory(link, peer.Public().Fingerprint, pinned); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestSignedOfflineInventoryRejectsInvalidSignedClaims(t *testing.T) {
	peer, _ := newOfflineIdentity(t)
	root := t.TempDir()
	writeOfflineFile(t, root, "safe", "v")
	dest := filepath.Join(t.TempDir(), "valid.json")
	bundle, err := ExportOfflineInventory(root, dest, nil, peer)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := deviceid.ParsePublic(peer.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		path string
	}{
		{"traversal", "../escape"}, {"absolute", "/etc/passwd"}, {"reserved", ".gcsync-stage-abc"}, {"duplicate", "safe"},
	} {
		t.Run(c.name, func(t *testing.T) {
			invalid := bundle
			invalid.Files = append(append([]BaselineEntry{}, bundle.Files...), BaselineEntry{Path: c.path, Size: 1, SHA256: strings.Repeat("a", 64)})
			payload, err := json.Marshal(invalid.OfflineInventoryBody)
			if err != nil {
				t.Fatal(err)
			}
			invalid.Signature = base64.RawURLEncoding.EncodeToString(peer.SignOfflineInventory(payload))
			out, _ := json.Marshal(invalid)
			p := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(p, out, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadOfflineInventory(p, peer.Public().Fingerprint, pub); err == nil {
				t.Fatal("malformed signed path accepted")
			}
		})
	}
}

func mustPub(t *testing.T, key string) []byte {
	t.Helper()
	pub, err := deviceid.ParsePublic(key)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestOfflineInventoryChallengeBinding(t *testing.T) {
	peer, _ := newOfflineIdentity(t)
	_, store := newOfflineIdentity(t)
	if _, err := deviceid.Trust(store, peer.Public().PublicKey, peer.Public().Fingerprint); err != nil {
		t.Fatal(err)
	}
	pinned, err := deviceid.Lookup(store, peer.Public().Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewOfflineInventoryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewOfflineInventoryChallenge()
	if err != nil || challenge == second || len(challenge) != 64 {
		t.Fatalf("challenges not independently random: %q / %q / %v", challenge, second, err)
	}
	if err := validateOfflineChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	root, local := t.TempDir(), t.TempDir()
	writeOfflineFile(t, root, "one.txt", "contents")
	writeOfflineFile(t, local, "one.txt", "contents")
	file := filepath.Join(t.TempDir(), "challenged.json")
	exported, err := ExportChallengedOfflineInventory(root, file, nil, peer, challenge)
	if err != nil || exported.Challenge != challenge {
		t.Fatalf("export challenge: %v %+v", err, exported)
	}
	read, err := ReadOfflineInventory(file, peer.Public().Fingerprint, pinned)
	if err != nil || read.Challenge != challenge {
		t.Fatalf("signed challenge not verified: %v", err)
	}
	comparison, err := CompareVerifiedOfflineInventoryWithChallenge(local, nil, file, peer.Public().Fingerprint, pinned, challenge)
	if err != nil || !comparison.ChallengeVerified || !comparison.Plan.ReadOnly || comparison.Plan.Identical != 1 {
		t.Fatalf("challenge-bound compare: %+v %v", comparison, err)
	}
	if _, err := CompareVerifiedOfflineInventory(local, nil, file, peer.Public().Fingerprint, pinned); err == nil {
		t.Fatal("challenged inventory silently accepted as unchallenged")
	}
	if _, err := CompareVerifiedOfflineInventoryWithChallenge(local, nil, file, peer.Public().Fingerprint, pinned, second); err == nil {
		t.Fatal("signed inventory reused with a different challenge")
	}
	legacy := filepath.Join(t.TempDir(), "legacy.json")
	if _, err := ExportOfflineInventory(root, legacy, nil, peer); err != nil {
		t.Fatal(err)
	}
	if _, err := CompareVerifiedOfflineInventoryWithChallenge(local, nil, legacy, peer.Public().Fingerprint, pinned, challenge); err == nil {
		t.Fatal("accepted unchallenged inventory for a challenged request")
	}
	if result, err := CompareVerifiedOfflineInventory(local, nil, legacy, peer.Public().Fingerprint, pinned); err != nil || result.ChallengeVerified {
		t.Fatalf("legacy comparison regressed: %v %+v", err, result)
	}
	if _, err := ExportChallengedOfflineInventory(root, filepath.Join(t.TempDir(), "invalid.json"), nil, peer, "ABC"); err == nil {
		t.Fatal("accepted malformed export challenge")
	}
	if _, err := CompareVerifiedOfflineInventoryWithChallenge(local, nil, file, peer.Public().Fingerprint, pinned, "ABC"); err == nil {
		t.Fatal("accepted malformed expected challenge")
	}
}

func TestOfflineInventorySignedChallengeTamperAndNoncanonical(t *testing.T) {
	peer, _ := newOfflineIdentity(t)
	root := t.TempDir()
	writeOfflineFile(t, root, "file.txt", "hello")
	challenge, err := NewOfflineInventoryChallenge()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "original.json")
	good, err := ExportChallengedOfflineInventory(root, file, nil, peer, challenge)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := deviceid.ParsePublic(peer.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		challenge string
		resign    bool
	}{
		{"unsigned challenge alteration", strings.Repeat("0", 64), false},
		{"signed uppercase challenge", strings.ToUpper(challenge), true},
		{"signed short challenge", "abcd", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := good
			item.Challenge = tc.challenge
			if tc.resign {
				payload, err := json.Marshal(item.OfflineInventoryBody)
				if err != nil {
					t.Fatal(err)
				}
				item.Signature = base64.RawURLEncoding.EncodeToString(peer.SignOfflineInventory(payload))
			}
			data, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			bad := filepath.Join(t.TempDir(), "bad.json")
			if err := os.WriteFile(bad, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadOfflineInventory(bad, peer.Public().Fingerprint, pub); err == nil {
				t.Fatal("malformed or tampered challenge accepted")
			}
		})
	}
}
