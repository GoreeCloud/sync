//go:build linux || android

package deviceid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestDeviceIdentityAncestorSymlinksFailClosed(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(filepath.Join(link, "identity")); err == nil {
		t.Fatal("created identity through symlinked ancestor")
	}
	if _, err := os.Lstat(filepath.Join(real, "identity")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created files beyond rejected symlink")
	}
	root := filepath.Join(real, "identity")
	if _, err := Initialize(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(link, "identity")); err == nil {
		t.Fatal("loaded identity through symlinked ancestor")
	}
	if _, err := List(filepath.Join(link, "identity")); err == nil {
		t.Fatal("listed trust through symlinked ancestor")
	}
	if err := createPrivateFile(filepath.Join(link, "identity"), "injected.json", []byte(`{"x":1}`)); err == nil {
		t.Fatal("created record through symlink")
	}
	if _, err := os.Lstat(filepath.Join(root, "injected.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("symlinked write reached real directory")
	}
}
func TestDeviceIdentityHardlinksAndSpecialFilesFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	if _, err := Initialize(root); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, identityName)
	alias := filepath.Join(root, "alias")
	if err := os.Link(key, alias); err != nil {
		t.Skipf("hardlinks unsupported: %v", err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted multiply-linked identity seed")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", key); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted symlink identity")
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	// A directory substituted as a record must fail immediately.
	if err := os.Mkdir(key, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted directory as identity")
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(key, 0600); err != nil {
		t.Skipf("FIFO not available: %v", err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("accepted FIFO as identity record")
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
}
func TestDeviceIdentityNoOverwriteAndPrivateStages(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	if _, err := Initialize(root); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, identityName))
	if err != nil {
		t.Fatal(err)
	}
	if err := createPrivateFile(root, identityName, []byte("wrong")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrote existing seed: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(root, identityName))
	if err != nil || string(after) != string(before) {
		t.Fatal("identity changed after overwrite attempt")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".gc-identity-stage-") {
			t.Fatalf("stage left over: %q", e.Name())
		}
	}
	st, err := os.Lstat(filepath.Join(root, identityName))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("identity not 0600: %v %v", st, err)
	}
}
func TestDeviceIdentityConcurrentTrustAndUntrust(t *testing.T) {
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if _, err := Initialize(a); err != nil {
		t.Fatal(err)
	}
	peer, err := Initialize(b)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := Trust(a, peer.PublicKey, peer.Fingerprint); results <- e }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else if !errors.Is(e, os.ErrExist) {
			t.Fatalf("unexpected trust failure: %v", e)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one trust: %d", successes)
	}
	if _, err := Lookup(a, peer.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := Untrust(a, peer.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(a, peer.Fingerprint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrust left record: %v", err)
	}
	if _, err := Trust(a, peer.PublicKey, peer.Fingerprint); err != nil {
		t.Fatal("trust after untrust failed:", err)
	}
}
func TestDeviceTrustSymlinkedParentAndHardlinkFailClosed(t *testing.T) {
	root, peerRoot := filepath.Join(t.TempDir(), "identity"), filepath.Join(t.TempDir(), "peer")
	if _, err := Initialize(root); err != nil {
		t.Fatal(err)
	}
	peer, err := Initialize(peerRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Trust(root, peer.PublicKey, peer.Fingerprint); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(root, "trusted", strings.TrimPrefix(peer.Fingerprint, "sha256:")+".json")
	hardlink := filepath.Join(root, "trusted", "other.json")
	if err := os.Link(rec, hardlink); err != nil {
		t.Skipf("hardlinks unsupported: %v", err)
	}
	if _, err := Lookup(root, peer.Fingerprint); err == nil {
		t.Fatal("accepted hardlinked trust record")
	}
	if err := Untrust(root, peer.Fingerprint); err == nil {
		t.Fatal("untrusted hardlinked record removed")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(root, peer.Fingerprint); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(root), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(alias, peer.Fingerprint); err == nil {
		t.Fatal("accepted symlinked trust ancestor")
	}
	if err := Untrust(alias, peer.Fingerprint); err == nil {
		t.Fatal("untrusted through symlink")
	}
	if _, err := Lookup(root, peer.Fingerprint); err != nil {
		t.Fatal("trust changed after rejected removal:", err)
	}
}
