//go:build linux || android

package syncplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

func newCommitTicket(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	folder := newProtectedPrivateFolder(t)
	file := filepath.Join(folder, "challenge.json")
	peer, _ := newOfflineIdentity(t)
	pub := peer.Public()
	pinned, err := deviceid.ParsePublic(pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueOneUseInventoryChallenge(file, root, pub.Fingerprint, nil, pinned); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var ticket oneUseTicket
	if err := json.Unmarshal(data, &ticket); err != nil {
		t.Fatal(err)
	}
	return file, ticket.SHA256
}

func TestTicketMarkerCommitUsesAnchoredParent(t *testing.T) {
	file, sha := newCommitTicket(t)
	folder := filepath.Dir(file)
	alias := filepath.Join(filepath.Dir(folder), "linked-ticket-folder")
	if err := os.Symlink(folder, alias); err != nil {
		t.Fatal(err)
	}
	if err := consumeOneUseTicket(filepath.Join(alias, filepath.Base(file)), sha); err == nil {
		t.Fatal("created a spent marker through a symlinked directory ancestor")
	}
	if _, err := os.Lstat(file + ".used"); !os.IsNotExist(err) {
		t.Fatal("symlink parent caused marker creation", err)
	}
	if err := consumeOneUseTicket(file, sha); err != nil {
		t.Fatal(err)
	}
	a, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Lstat(file + ".used")
	if err != nil || !os.SameFile(a, b) || b.Mode().Perm() != 0600 {
		t.Fatal("spent marker must pin the original private ticket inode", err)
	}
	if err := consumeOneUseTicket(file, sha); err == nil {
		t.Fatal("one-use ticket was spent twice")
	}
}

func TestTicketMarkerRefusesExistingMarkerWithoutOverwrite(t *testing.T) {
	file, sha := newCommitTicket(t)
	sentinel := []byte("existing marker must not change")
	if err := os.WriteFile(file+".used", sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumeOneUseTicket(file, sha); err == nil || !strings.Contains(err.Error(), "spent") {
		t.Fatal("already used ticket marker accepted", err)
	}
	got, err := os.ReadFile(file + ".used")
	if err != nil || string(got) != string(sentinel) {
		t.Fatal("overwrote existing marker", err)
	}
}

func TestTicketMarkerRefusesSymlinkMarkerWithoutOverwrite(t *testing.T) {
	file, sha := newCommitTicket(t)
	target := filepath.Join(t.TempDir(), "important")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file+".used"); err != nil {
		t.Fatal(err)
	}
	if err := consumeOneUseTicket(file, sha); err == nil {
		t.Fatal("replaced existing symlink marker")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "keep" {
		t.Fatal("symlink destination modified", err)
	}
}

func TestTicketMarkerRefusesTicketHardlink(t *testing.T) {
	file, sha := newCommitTicket(t)
	other := file + ".backup"
	if err := os.Link(file, other); err != nil {
		t.Fatal(err)
	}
	if err := consumeOneUseTicket(file, sha); err == nil {
		t.Fatal("accepted hardlinked ticket")
	}
	if _, err := os.Lstat(file + ".used"); !os.IsNotExist(err) {
		t.Fatal("failed hardlink check created marker", err)
	}
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if err := consumeOneUseTicket(file, sha); err != nil {
		t.Fatal("single-linked ticket should be usable", err)
	}
}

func TestTicketMarkerChecksOpenedTicketContents(t *testing.T) {
	file, sha := newCommitTicket(t)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "\"version\": 1", "\"version\": 2", 1))
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumeOneUseTicket(file, sha); err == nil {
		t.Fatal("marker created for mutated ticket")
	}
	if _, err := os.Lstat(file + ".used"); !os.IsNotExist(err) {
		t.Fatal("mutated ticket consumed", err)
	}
}

func TestTicketMarkerConcurrentOneWinnerWithPinnedFD(t *testing.T) {
	file, sha := newCommitTicket(t)
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- consumeOneUseTicket(file, sha)
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one marker commit, got %d", successes)
	}
}
