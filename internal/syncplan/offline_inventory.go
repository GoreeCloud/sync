package syncplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GoreeCloud/sync/internal/deviceid"
)

// OfflineInventoryVersion is experimental. The format is a signed read-only
// *claim* about one folder, not a backup, trusted clock, authorization to copy,
// or a live network sync state. No absolute root path or file contents are saved.
const OfflineInventoryVersion = 1

type OfflineInventoryBody struct {
	Version     int             `json:"version"`
	Fingerprint string          `json:"fingerprint"`
	CapturedAt  string          `json:"capturedAt"`
	Challenge   string          `json:"challenge,omitempty"`
	Excludes    []string        `json:"excludes"`
	Files       []BaselineEntry `json:"files"`
}

type OfflineInventory struct {
	OfflineInventoryBody
	Signature string `json:"signature"`
}

type OfflineComparison struct {
	Mode                    string `json:"mode"`
	TrustedPeer             string `json:"trustedPeer"`
	CapturedAt              string `json:"capturedAt"`
	ChallengeVerified       bool   `json:"challengeVerified,omitempty"`
	OneUseChallengeConsumed bool   `json:"oneUseChallengeConsumed,omitempty"`
	Plan                    Plan   `json:"plan"`
}

// NewOfflineInventoryChallenge creates a fresh request nonce. It is public,
// but must be independently associated with the intended comparison request.
func NewOfflineInventoryChallenge() (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate inventory challenge: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
}

func validateOfflineChallenge(value string) error {
	if len(value) != 64 {
		return errors.New("inventory challenge must be 64 lowercase hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return errors.New("inventory challenge must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func validateOfflineBody(b OfflineInventoryBody) error {
	if b.Version != OfflineInventoryVersion || len(b.Fingerprint) != 71 || !strings.HasPrefix(b.Fingerprint, "sha256:") {
		return errors.New("unsupported offline inventory version or fingerprint")
	}
	fp, err := hex.DecodeString(strings.TrimPrefix(b.Fingerprint, "sha256:"))
	if err != nil || len(fp) != 32 || b.Fingerprint != strings.ToLower(b.Fingerprint) {
		return errors.New("invalid signer fingerprint")
	}
	if b.Challenge != "" {
		if err := validateOfflineChallenge(b.Challenge); err != nil {
			return err
		}
	}
	stamp, err := time.Parse(time.RFC3339Nano, b.CapturedAt)
	if err != nil || stamp.Location() != time.UTC || stamp.Format(time.RFC3339Nano) != b.CapturedAt {
		return errors.New("non-canonical UTC capture timestamp")
	}
	excludes, err := normalizedExcludes(b.Excludes)
	if err != nil {
		return err
	}
	if len(excludes) != len(b.Excludes) {
		return errors.New("non-canonical excludes")
	}
	for i := range excludes {
		if excludes[i] != b.Excludes[i] {
			return errors.New("non-canonical excludes")
		}
	}
	if len(b.Files) > MaxBaselineFiles {
		return errors.New("too many offline inventory files")
	}
	prior := ""
	for _, f := range b.Files {
		if !validBaselinePath(f.Path) || f.Path <= prior || f.Size < 0 || len(f.SHA256) != 64 || strings.HasPrefix(path.Base(f.Path), ".gcsync-stage-") {
			return fmt.Errorf("invalid or unsorted offline inventory entry %q", f.Path)
		}
		digest, err := hex.DecodeString(f.SHA256)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != f.SHA256 || shouldExclude(f.Path, b.Excludes) {
			return fmt.Errorf("invalid hash or excluded path in offline inventory entry %q", f.Path)
		}
		prior = f.Path
	}
	return nil
}

func canonicalOfflinePayload(body OfflineInventoryBody) ([]byte, error) {
	if err := validateOfflineBody(body); err != nil {
		return nil, err
	}
	return json.Marshal(body)
}

// ensureOutsideScanRoot avoids recording an export as user content, including
// when either the source or export parent directory uses a symlink.
func ensureOutsideScanRoot(root, destination string) error {
	if destination == "" {
		return errors.New("inventory output path required")
	}
	rootResolved, err := resolvedRoot(root)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	candidate := filepath.Join(parent, filepath.Base(absolute))
	rel, err := filepath.Rel(rootResolved, candidate)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("offline inventory output must be outside scanned folder")
	}
	return nil
}

// ExportOfflineInventory scans only the local directory, signs canonical JSON
// with an explicit local device identity, and stores it as a private new file.
func ExportOfflineInventory(root, destination string, excludes []string, own *deviceid.Identity) (OfflineInventory, error) {
	return ExportChallengedOfflineInventory(root, destination, excludes, own, "")
}

// ExportChallengedOfflineInventory binds an inventory to a caller-supplied
// 256-bit request challenge. Empty is permitted only for legacy/manual exports.
func ExportChallengedOfflineInventory(root, destination string, excludes []string, own *deviceid.Identity, challenge string) (OfflineInventory, error) {
	var empty OfflineInventory
	if err := ensureOutsideScanRoot(root, destination); err != nil {
		return empty, err
	}
	out, data, err := buildSignedOfflineInventory(root, excludes, own, challenge)
	if err != nil {
		return empty, err
	}
	if err := privateNoOverwriteFile(destination, data); err != nil {
		return empty, err
	}
	return out, nil
}

func buildSignedOfflineInventory(root string, excludes []string, own *deviceid.Identity, challenge string) (OfflineInventory, []byte, error) {
	var empty OfflineInventory
	if own == nil {
		return empty, nil, errors.New("local signing identity required")
	}
	if challenge != "" {
		if err := validateOfflineChallenge(challenge); err != nil {
			return empty, nil, err
		}
	}
	canonical, err := normalizedExcludes(excludes)
	if err != nil {
		return empty, nil, err
	}
	files, err := inventory(root, canonical)
	if err != nil {
		return empty, nil, err
	}
	if len(files) > MaxBaselineFiles {
		return empty, nil, errors.New("too many inventory entries")
	}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	entries := make([]BaselineEntry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, BaselineEntry{Path: k, Size: files[k].Size, SHA256: files[k].SHA256})
	}
	body := OfflineInventoryBody{Version: OfflineInventoryVersion, Fingerprint: own.Public().Fingerprint, CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), Challenge: challenge, Excludes: canonical, Files: entries}
	payload, err := canonicalOfflinePayload(body)
	if err != nil {
		return empty, nil, err
	}
	out := OfflineInventory{OfflineInventoryBody: body, Signature: base64.RawURLEncoding.EncodeToString(own.SignOfflineInventory(payload))}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return empty, nil, err
	}
	data = append(data, '\n')
	if len(data) > MaxBaselineBytes {
		return empty, nil, errors.New("offline inventory exceeds 16 MiB")
	}
	return out, data, nil
}

// ReadOfflineInventory validates untrusted JSON and a signature using the
// *previously pinned* peer key. It never imports paths as filesystem writes.
func ReadOfflineInventory(filename, expectedFingerprint string, pinned ed25519.PublicKey) (OfflineInventory, error) {
	var empty OfflineInventory
	if expectedFingerprint != deviceid.Fingerprint(pinned) {
		return empty, errors.New("expected fingerprint does not match previously trusted public key")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return empty, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBaselineBytes || info.Size() < 32 {
		return empty, errors.New("offline inventory is not a bounded regular file")
	}
	f, err := openProtectedRegularFile(filename)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return empty, errors.New("inventory path changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBaselineBytes+1))
	if err != nil || len(data) > MaxBaselineBytes {
		return empty, errors.New("offline inventory too large or unreadable")
	}
	return verifyOfflineInventoryData(data, expectedFingerprint, pinned)
}

// verifyOfflineInventoryData checks canonical signed content in memory after
// the caller has enforced a bounded file read or authenticated decryption.
func verifyOfflineInventoryData(data []byte, expectedFingerprint string, pinned ed25519.PublicKey) (OfflineInventory, error) {
	var empty OfflineInventory
	if expectedFingerprint != deviceid.Fingerprint(pinned) || len(data) < 32 || len(data) > MaxBaselineBytes {
		return empty, errors.New("invalid inventory size or untrusted peer key")
	}
	var result OfflineInventory
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return empty, fmt.Errorf("invalid inventory JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return empty, errors.New("unexpected trailing inventory JSON")
	}
	payload, err := canonicalOfflinePayload(result.OfflineInventoryBody)
	if err != nil {
		return empty, err
	}
	if result.Fingerprint != expectedFingerprint {
		return empty, errors.New("untrusted inventory signing identity")
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.Signature)
	if err != nil || !deviceid.VerifyOfflineInventory(pinned, payload, signature) {
		return empty, errors.New("offline inventory signature invalid")
	}
	return result, nil
}

// CompareVerifiedOfflineInventory requires cryptographic verification and a
// previously pinned peer identity in the same call as comparison. Callers
// cannot accidentally bypass signature checks by passing an arbitrary struct.
func CompareVerifiedOfflineInventory(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey) (OfflineComparison, error) {
	return compareVerifiedOfflineInventory(root, excludes, filename, fingerprint, pinned, "", "")
}

// CompareVerifiedOfflineInventoryWithChallenge binds the signed inventory to
// a fresh request. Neither an older unchallenged inventory nor a signed
// inventory for a different request can satisfy this comparison.
func CompareVerifiedOfflineInventoryWithChallenge(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey, expectedChallenge string) (OfflineComparison, error) {
	if err := validateOfflineChallenge(expectedChallenge); err != nil {
		return OfflineComparison{}, err
	}
	return compareVerifiedOfflineInventory(root, excludes, filename, fingerprint, pinned, expectedChallenge, "")
}

func compareVerifiedOfflineInventory(root string, excludes []string, filename, fingerprint string, pinned ed25519.PublicKey, expectedChallenge, keyFile string) (OfflineComparison, error) {
	var remote OfflineInventory
	var err error
	if keyFile == "" {
		remote, err = ReadOfflineInventory(filename, fingerprint, pinned)
	} else {
		remote, err = ReadEncryptedOfflineInventory(filename, fingerprint, pinned, keyFile)
	}
	if err != nil {
		return OfflineComparison{}, err
	}
	// Challenged exports may not be accidentally treated as an unchallenged
	// comparison. This enforces the request binding even for legacy callers.
	if remote.Challenge != "" || expectedChallenge != "" {
		if remote.Challenge == "" || expectedChallenge == "" || subtle.ConstantTimeCompare([]byte(remote.Challenge), []byte(expectedChallenge)) != 1 {
			return OfflineComparison{}, errors.New("signed inventory challenge is missing, unexpected, or mismatched")
		}
	}
	comparison, err := compareOfflineInventory(root, excludes, remote)
	if err != nil {
		return OfflineComparison{}, err
	}
	comparison.ChallengeVerified = expectedChallenge != ""
	return comparison, nil
}

// compareOfflineInventory is private because imported snapshot structs must
// first pass the strict signature check in ReadOfflineInventory.
func compareOfflineInventory(root string, excludes []string, remote OfflineInventory) (OfflineComparison, error) {
	var out OfflineComparison
	canonical, err := normalizedExcludes(excludes)
	if err != nil {
		return out, err
	}
	if len(canonical) != len(remote.Excludes) {
		return out, errors.New("local excludes must exactly match remote capture")
	}
	for i := range canonical {
		if canonical[i] != remote.Excludes[i] {
			return out, errors.New("local excludes must exactly match remote capture")
		}
	}
	files, err := inventory(root, canonical)
	if err != nil {
		return out, err
	}
	remoteMap := make(map[string]File, len(remote.Files))
	for _, e := range remote.Files {
		remoteMap[e.Path] = File{Size: e.Size, SHA256: e.SHA256}
	}
	keys, seen := make([]string, 0, len(files)+len(remoteMap)), make(map[string]bool)
	for k := range files {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range remoteMap {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	p := Plan{ReadOnly: true, Changes: make([]Change, 0, len(keys)), SourceFiles: len(files), TargetFiles: len(remoteMap)}
	for _, k := range keys {
		local, localOK := files[k]
		peer, peerOK := remoteMap[k]
		ch := Change{Path: k}
		switch {
		case !localOK:
			ch.Status = "target-only"
			ch.Target = &peer
			p.TargetOnly++
		case !peerOK:
			ch.Status = "source-only"
			ch.Source = &local
			p.SourceOnly++
		case local == peer:
			ch.Status = "identical"
			ch.Source = &local
			ch.Target = &peer
			p.Identical++
		default:
			ch.Status = "different"
			ch.Source = &local
			ch.Target = &peer
			p.Different++
		}
		p.Changes = append(p.Changes, ch)
	}
	return OfflineComparison{Mode: "signed-offline-inventory", TrustedPeer: remote.Fingerprint, CapturedAt: remote.CapturedAt, Plan: p}, nil
}
