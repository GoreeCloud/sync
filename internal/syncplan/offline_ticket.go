package syncplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

// OneUseChallengeTicket is experimental local request state. The issued file
// must be retained alongside its .used hardlink after consumption; restoring a
// filesystem backup or deleting .used can undo the replay guard.
const oneUseTicketVersion = 1
const oneUseTicketLifetime = 24 * time.Hour

type ticketBody struct {
	Version         int      `json:"version"`
	Challenge       string   `json:"challenge"`
	PeerFingerprint string   `json:"peerFingerprint"`
	LocalRoot       string   `json:"localRoot"`
	Excludes        []string `json:"excludes"`
	IssuedAt        string   `json:"issuedAt"`
}

type oneUseTicket struct {
	ticketBody
	SHA256 string `json:"sha256"`
}

func ticketHash(body ticketBody) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func privateTicketParent(filename string) error {
	if filename == "" || filepath.Base(filename) == "." || filepath.Base(filename) == ".." {
		return errors.New("one-use challenge ticket path required")
	}
	parent := filepath.Dir(filename)
	stat, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm() != 0700 {
		return errors.New("one-use challenge ticket parent must be a real private 0700 directory")
	}
	return nil
}

func canonicalTicketExcludes(excludes []string) ([]string, error) {
	canonical, err := normalizedExcludes(excludes)
	if err != nil {
		return nil, err
	}
	if canonical == nil {
		canonical = []string{}
	}
	return canonical, nil
}

// IssueOneUseInventoryChallenge creates a new private 0600 ticket that binds a
// fresh random challenge to the intended peer, local folder and exclusions.
// It never overwrites, and refuses to issue inside the scanned folder.
func IssueOneUseInventoryChallenge(filename, root, fingerprint string, excludes []string, pinned ed25519.PublicKey) (string, error) {
	if fingerprint == "" || fingerprint != deviceid.Fingerprint(pinned) {
		return "", errors.New("ticket requires previously trusted peer fingerprint")
	}
	if err := privateTicketParent(filename); err != nil {
		return "", err
	}
	if err := ensureOutsideScanRoot(root, filename); err != nil {
		return "", err
	}
	if _, err := os.Lstat(filename + ".used"); err == nil {
		return "", errors.New("already spent ticket name cannot be reissued")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	canonical, err := canonicalTicketExcludes(excludes)
	if err != nil {
		return "", err
	}
	resolved, err := resolvedRoot(root)
	if err != nil {
		return "", err
	}
	challenge, err := NewOfflineInventoryChallenge()
	if err != nil {
		return "", err
	}
	body := ticketBody{Version: oneUseTicketVersion, Challenge: challenge, PeerFingerprint: fingerprint, LocalRoot: resolved, Excludes: canonical, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	hash, err := ticketHash(body)
	if err != nil {
		return "", err
	}
	payload, err := json.MarshalIndent(oneUseTicket{ticketBody: body, SHA256: hash}, "", "  ")
	if err != nil {
		return "", err
	}
	payload = append(payload, '\n')
	if err := privateNoOverwriteFile(filename, payload); err != nil {
		return "", err
	}
	return challenge, nil
}

func loadOneUseTicket(filename, root, fingerprint string, excludes []string, pinned ed25519.PublicKey) (oneUseTicket, error) {
	var empty oneUseTicket
	if err := privateTicketParent(filename); err != nil {
		return empty, err
	}
	if err := ensureOutsideScanRoot(root, filename); err != nil {
		return empty, err
	}
	if _, err := os.Lstat(filename + ".used"); err == nil {
		return empty, errors.New("one-use inventory challenge ticket already spent")
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	stat, err := os.Lstat(filename)
	if err != nil {
		return empty, err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || stat.Size() > 4096 || stat.Size() < 64 {
		return empty, errors.New("ticket must be a bounded private 0600 regular file")
	}
	f, err := openProtectedRegularFile(filename)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(stat, opened) || !uniquePrivateFileLink(opened) {
		return empty, errors.New("ticket changed while opening or has additional hardlinks")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return empty, errors.New("ticket unreadable or too large")
	}
	var t oneUseTicket
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return empty, fmt.Errorf("invalid ticket JSON: %w", err)
	}
	var next any
	if err := dec.Decode(&next); err != io.EOF {
		return empty, errors.New("trailing ticket JSON")
	}
	if t.Version != oneUseTicketVersion || validateOfflineChallenge(t.Challenge) != nil || fingerprint == "" || fingerprint != deviceid.Fingerprint(pinned) || t.PeerFingerprint != fingerprint {
		return empty, errors.New("ticket version, challenge or pinned peer mismatch")
	}
	rootResolved, err := resolvedRoot(root)
	if err != nil {
		return empty, err
	}
	if t.LocalRoot != rootResolved {
		return empty, errors.New("ticket bound to a different local folder")
	}
	canonical, err := canonicalTicketExcludes(excludes)
	if err != nil {
		return empty, err
	}
	if len(canonical) != len(t.Excludes) {
		return empty, errors.New("ticket exclusion policy mismatch")
	}
	for i := range canonical {
		if canonical[i] != t.Excludes[i] {
			return empty, errors.New("ticket exclusion policy mismatch")
		}
	}
	timeIssued, err := time.Parse(time.RFC3339Nano, t.IssuedAt)
	if err != nil || timeIssued.Location() != time.UTC || timeIssued.Format(time.RFC3339Nano) != t.IssuedAt {
		return empty, errors.New("ticket noncanonical timestamp")
	}
	now := time.Now().UTC()
	if now.Before(timeIssued.Add(-5*time.Minute)) || !now.Before(timeIssued.Add(oneUseTicketLifetime)) {
		return empty, errors.New("ticket expired or local clock moved back")
	}
	h, err := ticketHash(t.ticketBody)
	if err != nil || h != t.SHA256 {
		return empty, errors.New("ticket checksum mismatch")
	}
	return t, nil
}

// verifyTicketAtCommit rejects a changed ticket *through the opened inode*
// immediately before the one-winner marker is linked. Earlier load/compare
// checks also bind the ticket to the trusted peer, roots, exclusions and time.
func verifyTicketAtCommit(f *os.File, expectedSHA string) (os.FileInfo, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || !uniquePrivateFileLink(stat) || stat.Size() < 64 || stat.Size() > 4096 {
		return nil, errors.New("one-use ticket inode must be a private, single-linked bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("one-use ticket changed or exceeds size bound at commit")
	}
	var ticket oneUseTicket
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&ticket); err != nil {
		return nil, fmt.Errorf("invalid one-use ticket at commit: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("one-use ticket has trailing JSON at commit")
	}
	sha, err := ticketHash(ticket.ticketBody)
	if err != nil || sha != expectedSHA || ticket.SHA256 != sha {
		return nil, errors.New("one-use ticket content changed before commit")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(stat, after) || after.Size() != stat.Size() || after.ModTime() != stat.ModTime() {
		return nil, errors.New("one-use ticket inode changed during commit verification")
	}
	return stat, nil
}

// CompareWithOneUseInventoryTicket verifies a signed, challenged peer response,
// then consumes its local ticket atomically *before* returning a comparison.
// Consume uses an immutable no-overwrite hardlink marker, so concurrent calls
// cannot both succeed. The marker is durable before a result is returned.
func CompareWithOneUseInventoryTicket(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey, ticketPath string) (OfflineComparison, error) {
	return compareWithOneUseInventoryTicket(root, excludes, filename, fingerprint, pinned, ticketPath, "")
}

// CompareWithEncryptedOneUseInventoryTicket consumes a ticket only after the
// encrypted envelope, pinned signature, and exact challenge all verify.
func CompareWithEncryptedOneUseInventoryTicket(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey, ticketPath, keyFile string) (OfflineComparison, error) {
	if keyFile == "" {
		return OfflineComparison{}, errors.New("encrypted ticket comparison requires key file")
	}
	if err := ensureOutsideScanRoot(root, keyFile); err != nil {
		return OfflineComparison{}, fmt.Errorf("inventory key must be stored outside compared folder: %w", err)
	}
	return compareWithOneUseInventoryTicket(root, excludes, filename, fingerprint, pinned, ticketPath, keyFile)
}

func compareWithOneUseInventoryTicket(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey, ticketPath, keyFile string) (OfflineComparison, error) {
	ticket, err := loadOneUseTicket(ticketPath, root, fingerprint, excludes, pinned)
	if err != nil {
		return OfflineComparison{}, err
	}
	comparison, err := compareVerifiedOfflineInventory(root, excludes, filename, fingerprint, pinned, ticket.Challenge, keyFile)
	if err != nil {
		return OfflineComparison{}, err
	}
	// Recheck that the ticket inode and contents have not changed while scanning.
	repeated, err := loadOneUseTicket(ticketPath, root, fingerprint, excludes, pinned)
	if err != nil || repeated.SHA256 != ticket.SHA256 {
		return OfflineComparison{}, errors.New("one-use ticket changed or was consumed during comparison")
	}
	// This hardlink is the one-winner, crash-persistent commit point. On
	// Linux/Android, publish it through a pinned private directory descriptor;
	// reopening pathnames here would undo the offline-artifact I/O hardening.
	if err := consumeOneUseTicket(ticketPath, ticket.SHA256); err != nil {
		return OfflineComparison{}, err
	}
	comparison.ChallengeVerified = true
	comparison.OneUseChallengeConsumed = true
	return comparison, nil
}
