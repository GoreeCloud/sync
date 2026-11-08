package syncplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

func ticketFixture(t *testing.T) (root, remote, ticketPath, response, fp string, pinned []byte, peer *deviceid.Identity) {
	t.Helper()
	peer, _ = newOfflineIdentity(t)
	root, remote = t.TempDir(), t.TempDir()
	writeOfflineFile(t, root, "shared.txt", "same")
	writeOfflineFile(t, remote, "shared.txt", "same")
	ticketDir := t.TempDir()
	if err := os.Chmod(ticketDir, 0700); err != nil {
		t.Fatal(err)
	}
	ticketPath = filepath.Join(ticketDir, "request.json")
	response = filepath.Join(t.TempDir(), "signed.json")
	fp = peer.Public().Fingerprint
	var err error
	pinned, err = deviceid.ParsePublic(peer.Public().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestOneUseOfflineTicketConsumedAndPersists(t *testing.T) {
	local, remote, ticket, response, fp, pinned, peer := ticketFixture(t)
	challenge, err := IssueOneUseInventoryChallenge(ticket, local, fp, nil, pinned)
	if err != nil || validateOfflineChallenge(challenge) != nil {
		t.Fatalf("issue: %v", err)
	}
	info, err := os.Stat(ticket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("ticket mode: %v %v", info, err)
	}
	if _, err = IssueOneUseInventoryChallenge(ticket, local, fp, nil, pinned); err == nil {
		t.Fatal("reissued existing ticket")
	}
	if _, err = ExportChallengedOfflineInventory(remote, response, nil, peer, challenge); err != nil {
		t.Fatal(err)
	}
	result, err := CompareWithOneUseInventoryTicket(local, nil, response, fp, pinned, ticket)
	if err != nil || !result.ChallengeVerified || !result.OneUseChallengeConsumed || result.Plan.Identical != 1 {
		t.Fatalf("compare: %+v %v", result, err)
	}
	spent, err := os.Stat(ticket + ".used")
	if err != nil || !os.SameFile(info, spent) {
		t.Fatalf("durable marker missing or wrong inode: %v", err)
	}
	// New comparison from the same process or after a fresh startup fails.
	if _, err = CompareWithOneUseInventoryTicket(local, nil, response, fp, pinned, ticket); err == nil {
		t.Fatal("replay accepted")
	}
	// A renamed/removed issued file cannot make the same issued name reusable.
	if err := os.Remove(ticket); err != nil {
		t.Fatal(err)
	}
	if _, err = IssueOneUseInventoryChallenge(ticket, local, fp, nil, pinned); err == nil {
		t.Fatal("spent marker ignored by issuer")
	}
}

func TestOneUseTicketBadResponseDoesNotConsume(t *testing.T) {
	local, remote, ticket, response, fp, pinned, peer := ticketFixture(t)
	challenge, err := IssueOneUseInventoryChallenge(ticket, local, fp, []string{"*.tmp"}, pinned)
	if err != nil {
		t.Fatal(err)
	}
	different, _ := NewOfflineInventoryChallenge()
	if _, err = ExportChallengedOfflineInventory(remote, response, []string{"*.tmp"}, peer, different); err != nil {
		t.Fatal(err)
	}
	if _, err = CompareWithOneUseInventoryTicket(local, []string{"*.tmp"}, response, fp, pinned, ticket); err == nil {
		t.Fatal("mismatched challenge accepted")
	}
	if _, err = os.Stat(ticket + ".used"); !os.IsNotExist(err) {
		t.Fatal("failed verification consumed ticket")
	}
	good := filepath.Join(t.TempDir(), "good.json")
	if _, err = ExportChallengedOfflineInventory(remote, good, []string{"*.tmp"}, peer, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err = CompareWithOneUseInventoryTicket(local, nil, good, fp, pinned, ticket); err == nil {
		t.Fatal("changed excludes accepted")
	}
	if _, err = CompareWithOneUseInventoryTicket(remote, []string{"*.tmp"}, good, fp, pinned, ticket); err == nil {
		t.Fatal("changed local root accepted")
	}
	if _, err = CompareWithOneUseInventoryTicket(local, []string{"*.tmp"}, good, fp, pinned, ticket); err != nil {
		t.Fatal(err)
	}
}

func TestOneUseTicketCorruptionPermissionsAndExpiry(t *testing.T) {
	local, _, ticket, _, fp, pinned, _ := ticketFixture(t)
	if _, err := IssueOneUseInventoryChallenge(filepath.Join(local, "request"), local, fp, nil, pinned); err == nil {
		t.Fatal("allowed ticket in scan folder")
	}
	if _, err := IssueOneUseInventoryChallenge(ticket, local, fp, nil, pinned); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ticket, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOneUseTicket(ticket, local, fp, nil, pinned); err == nil {
		t.Fatal("accepted public ticket")
	}
	if err := os.Chmod(ticket, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ticket, []byte(strings.Replace(string(orig), "\"version\": 1", "\"version\": 2", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOneUseTicket(ticket, local, fp, nil, pinned); err == nil {
		t.Fatal("accepted tampered ticket")
	}
	if err := os.WriteFile(ticket, orig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(ticket), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOneUseTicket(ticket, local, fp, nil, pinned); err == nil {
		t.Fatal("accepted insecure ticket directory")
	}
	if err := os.Chmod(filepath.Dir(ticket), 0700); err != nil {
		t.Fatal(err)
	}
	var x oneUseTicket
	if err := json.Unmarshal(orig, &x); err != nil {
		t.Fatal(err)
	}
	x.IssuedAt = time.Now().UTC().Add(-25 * time.Hour).Format(time.RFC3339Nano)
	x.SHA256, err = ticketHash(x.ticketBody)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ticket, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOneUseTicket(ticket, local, fp, nil, pinned); err == nil {
		t.Fatal("accepted expired ticket")
	}
	link := filepath.Join(t.TempDir(), "symlink.json")
	if err := os.Symlink(ticket, link); err == nil {
		if _, err := loadOneUseTicket(link, local, fp, nil, pinned); err == nil {
			t.Fatal("accepted symlinked ticket")
		}
	}
}

func TestOneUseTicketConcurrentOnlyOneWinner(t *testing.T) {
	local, remote, ticket, response, fp, pinned, peer := ticketFixture(t)
	challenge, err := IssueOneUseInventoryChallenge(ticket, local, fp, nil, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ExportChallengedOfflineInventory(remote, response, nil, peer, challenge); err != nil {
		t.Fatal(err)
	}
	const parallel = 8
	var wg sync.WaitGroup
	results := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := CompareWithOneUseInventoryTicket(local, nil, response, fp, pinned, ticket)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected one successful consumption, got %d", successes)
	}
}
