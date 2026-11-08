package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GoreeCloud/sync/internal/deviceid"
	"github.com/GoreeCloud/sync/internal/lansend"
	"github.com/GoreeCloud/sync/internal/syncplan"
)

const maxCiphertext int64 = 20 << 20
const maxStorage int64 = 256 << 20
const maxShareRecords = 512
const maxUploadAttemptsPerMinute = 60

//go:embed web/*
var web embed.FS

type share struct {
	ID           string    `json:"id"`
	Expires      time.Time `json:"expires"`
	Meta         string    `json:"meta"`
	Size         int64     `json:"size"`
	Limit        int       `json:"limit"`
	Count        int       `json:"count"`
	RevokeDigest string    `json:"revokeDigest,omitempty"`
	CipherSHA256 string    `json:"cipherSHA256,omitempty"`
}
type app struct {
	dir     string
	mu      sync.Mutex
	shares  map[string]*share
	size    int64
	now     func() time.Time
	uploads chan struct{}
	// Fixed-window local admission control is defense in depth against a
	// runaway client. All fields are protected by a.mu. This is not a
	// public-service abuse system or persistent distributed rate limit.
	uploadWindow time.Time
	uploadCount  int
}

func newApp(dir string) (*app, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("storage directory must have 0700 permissions")
	}
	a := &app{dir: dir, shares: map[string]*share{}, now: time.Now, uploads: make(chan struct{}, 4)}
	list, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range list {
		// A crash can leave ciphertext/metadata temporary files behind. Only
		// remove app-owned, regular temporary files that are at least 1 hour
		// old; never touch unrelated files in the configured directory.
		if (strings.HasPrefix(f.Name(), "upload-") && len(f.Name()) > len("upload-")) ||
			(strings.HasPrefix(f.Name(), "meta-") && len(f.Name()) > len("meta-")) {
			if f.Type().IsRegular() {
				if st, err := f.Info(); err == nil && st.ModTime().Before(a.now().Add(-time.Hour)) {
					_ = os.Remove(filepath.Join(dir, f.Name()))
				}
			}
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".json")
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") || !validID(id) || f.Type()&os.ModeSymlink != 0 {
			continue
		}
		bytes, err := os.ReadFile(a.path(id, ".json"))
		if err != nil {
			continue
		}
		var s share
		if json.Unmarshal(bytes, &s) != nil || s.ID != id || s.Size < 32 || s.Size > maxCiphertext || s.Limit < 1 || s.Limit > 5 || s.Count < 0 || s.Count > s.Limit {
			continue
		}
		fi, err := os.Lstat(a.path(id, ".bin"))
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != s.Size {
			continue
		}
		if !a.now().Before(s.Expires) {
			_ = os.Remove(a.path(id, ".json"))
			_ = os.Remove(a.path(id, ".bin"))
			continue
		}
		a.shares[id] = &s
		a.size += s.Size
	}
	return a, nil
}
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
func (a *app) path(id, ext string) string { return filepath.Join(a.dir, id+ext) }
func (a *app) clean() {
	for id, s := range a.shares {
		if !a.now().Before(s.Expires) {
			// Never forget expired ciphertext if deletion failed; retry later.
			if err := os.Remove(a.path(id, ".bin")); err != nil && !errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err := os.Remove(a.path(id, ".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				continue
			}
			a.size -= s.Size
			delete(a.shares, id)
		}
	}
}

// pruneExpired holds the lock while removing expired ciphertext and metadata.
func (a *app) pruneExpired() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clean()
}

// runJanitor prunes expired shares even if no new requests arrive.
func (a *app) runJanitor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pruneExpired()
		}
	}
}

func validHost(host string) bool {
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	ip := net.ParseIP(name)
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && ip != nil && ip.IsLoopback()
}

// diskCiphertextBytes counts active, orphaned and in-flight opaque data. A
// previous crash may have left unindexed blobs; such bytes must still count
// against the temporary storage quota even if they are not retrievable.
// The caller must hold a.mu when this is used to approve a new share.
func (a *app) diskCiphertextBytes() (int64, error) {
	items, err := os.ReadDir(a.dir)
	if err != nil {
		return 0, err
	}
	var used int64
	for _, item := range items {
		name := item.Name()
		ownedBlob := strings.HasSuffix(name, ".bin") && validID(strings.TrimSuffix(name, ".bin"))
		temporary := strings.HasPrefix(name, "upload-")
		if !ownedBlob && !temporary {
			continue
		}
		// Treat unexpected filesystem objects conservatively; an attacker
		// with access to a private store is outside this preview's model.
		if !item.Type().IsRegular() {
			continue
		}
		info, err := item.Info()
		if err != nil {
			return 0, err
		}
		if info.Size() > maxStorage-used {
			return maxStorage + 1, nil
		}
		used += info.Size()
	}
	return used, nil
}

func (a *app) save(s *share) error {
	tmp, err := os.CreateTemp(a.dir, "meta-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	err = json.NewEncoder(tmp).Encode(s)
	if err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.path(s.ID, ".json"))
}
func errorJSON(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func intHeader(r *http.Request, key string, def, min, max int) (int, error) {
	str := r.Header.Get(key)
	if str == "" {
		return def, nil
	}
	i, err := strconv.Atoi(str)
	if err != nil || i < min || i > max {
		return 0, errors.New("invalid range")
	}
	return i, nil
}
func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}
func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	secure(w)
	// Browsers can be tricked into reaching loopback via DNS rebinding.
	// Reject all non-IP loopback Host values, even for static resources.
	if !validHost(r.Host) {
		errorJSON(w, http.StatusForbidden, "invalid local host")
		return
	}
	// Metadata-reading cross-site requests and image-triggered downloads are denied.
	if strings.HasPrefix(r.URL.Path, "/api/shares") && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		errorJSON(w, http.StatusForbidden, "cross-site request denied")
		return
	}
	switch {
	case r.URL.Path == "/api/health" && r.Method == "GET":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`)
	case r.URL.Path == "/api/shares" && r.Method == "POST":
		a.upload(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/shares/") && strings.HasSuffix(r.URL.Path, "/revoke") && r.Method == "POST":
		a.revoke(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/shares/"), "/revoke"))
	case strings.HasPrefix(r.URL.Path, "/api/shares/") && r.Method == "GET":
		a.download(w, r, strings.TrimPrefix(r.URL.Path, "/api/shares/"))
	case r.Method == "GET" && (r.URL.Path == "/" || (strings.HasPrefix(r.URL.Path, "/s/") && validID(strings.TrimPrefix(r.URL.Path, "/s/")))):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		b, _ := web.ReadFile("web/index.html")
		w.Write(b)
	case r.Method == "GET" && (r.URL.Path == "/style.css" || r.URL.Path == "/app.js"):
		name := "web" + r.URL.Path
		b, err := web.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(name, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		w.Write(b)
	default:
		http.NotFound(w, r)
	}
}
func (a *app) upload(w http.ResponseWriter, r *http.Request) {
	select {
	case a.uploads <- struct{}{}:
		defer func() { <-a.uploads }()
	default:
		errorJSON(w, http.StatusTooManyRequests, "too many concurrent uploads")
		return
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		errorJSON(w, 415, "expected encrypted octet-stream")
		return
	}
	if r.Header.Get("X-GC-Client") != "web-v1" {
		errorJSON(w, 400, "invalid client protocol")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "http://"+r.Host {
		errorJSON(w, 403, "origin denied")
		return
	}
	meta := r.Header.Get("X-GC-Meta")
	decoded, err := base64.RawURLEncoding.DecodeString(meta)
	if err != nil || len(decoded) < 28 || len(decoded) > 4096 {
		errorJSON(w, 400, "invalid encrypted metadata")
		return
	}
	ttl, err := intHeader(r, "X-GC-TTL", 3600, 300, 86400)
	if err != nil {
		errorJSON(w, 400, "invalid expiry")
		return
	}
	revokeDigest := r.Header.Get("X-GC-Revoke-Digest")
	rawDigest, digestErr := base64.RawURLEncoding.DecodeString(revokeDigest)
	if digestErr != nil || len(rawDigest) != sha256.Size {
		errorJSON(w, 400, "missing or invalid revocation digest")
		return
	}
	limit, err := intHeader(r, "X-GC-Downloads", 1, 1, 5)
	if err != nil {
		errorJSON(w, 400, "invalid download count")
		return
	}
	// Reject excess submissions before accepting up to 20 MiB of bytes.
	// Rate-count accepted header-level attempts, including bad ciphertext,
	// rather than permitting an attacker to retry malformed content forever.
	a.mu.Lock()
	a.clean()
	now := a.now()
	if a.uploadWindow.IsZero() || now.Before(a.uploadWindow) || now.Sub(a.uploadWindow) >= time.Minute {
		a.uploadWindow = now
		a.uploadCount = 0
	}
	if a.uploadCount >= maxUploadAttemptsPerMinute {
		a.mu.Unlock()
		errorJSON(w, http.StatusTooManyRequests, "upload attempt rate exceeded")
		return
	}
	if len(a.shares) >= maxShareRecords {
		a.mu.Unlock()
		errorJSON(w, http.StatusInsufficientStorage, "maximum share records reached")
		return
	}
	a.uploadCount++
	a.mu.Unlock()
	f, err := os.CreateTemp(a.dir, "upload-")
	if err != nil {
		errorJSON(w, 500, "storage error")
		return
	}
	defer os.Remove(f.Name())
	_ = f.Chmod(0600)
	checksum := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, checksum), io.LimitReader(r.Body, maxCiphertext+1))
	if err != nil || n < 32 || n > maxCiphertext {
		f.Close()
		errorJSON(w, 413, "invalid or oversized ciphertext")
		return
	}
	if _, err = f.Seek(0, 0); err != nil {
		f.Close()
		errorJSON(w, 500, "storage error")
		return
	}
	var magic [4]byte
	_, err = io.ReadFull(f, magic[:])
	if err != nil || string(magic[:]) != "GCS1" {
		f.Close()
		errorJSON(w, 400, "bad ciphertext envelope")
		return
	}
	if err = f.Sync(); err != nil {
		f.Close()
		errorJSON(w, 500, "storage error")
		return
	}
	if err = f.Close(); err != nil {
		errorJSON(w, 500, "storage error")
		return
	}
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		errorJSON(w, 500, "random unavailable")
		return
	}
	id := hex.EncodeToString(raw)
	s := &share{ID: id, Expires: a.now().Add(time.Duration(ttl) * time.Second), Meta: meta, Size: n, Limit: limit, RevokeDigest: revokeDigest, CipherSHA256: base64.RawURLEncoding.EncodeToString(checksum.Sum(nil))}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clean()
	// Another concurrently running upload may have filled the final slot
	// after our initial admission check.
	if len(a.shares) >= maxShareRecords {
		errorJSON(w, http.StatusInsufficientStorage, "maximum share records reached")
		return
	}
	diskUsed, err := a.diskCiphertextBytes()
	if err != nil {
		errorJSON(w, 500, "storage quota verification failed")
		return
	}
	// diskUsed already includes the still-present upload-NNN temporary file.
	if a.size+n > maxStorage || diskUsed > maxStorage {
		errorJSON(w, 507, "storage quota reached")
		return
	}
	if err = os.Rename(f.Name(), a.path(id, ".bin")); err != nil {
		errorJSON(w, 500, "storage error")
		return
	}
	if err = a.save(s); err != nil {
		_ = os.Remove(a.path(id, ".bin"))
		errorJSON(w, 500, "storage error")
		return
	}
	a.shares[id] = s
	a.size += n
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "expiresAt": s.Expires})
}

// revoke accepts an owner-only secret separate from the public decryptable link.
// The server stores only its SHA-256 digest and compares in constant time.
func (a *app) revoke(w http.ResponseWriter, r *http.Request, id string) {
	if !validID(id) {
		errorJSON(w, 404, "invalid share id")
		return
	}
	if r.Header.Get("X-GC-Client") != "web-v1" || r.Header.Get("Origin") != "http://"+r.Host {
		errorJSON(w, 403, "request not authorized by origin")
		return
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-GC-Revoke-Token"))
	if err != nil || len(rawToken) != 32 {
		errorJSON(w, 403, "invalid revocation token")
		return
	}
	digest := sha256.Sum256(rawToken)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clean()
	s, ok := a.shares[id]
	if !ok {
		errorJSON(w, 404, "share not found or expired")
		return
	}
	stored, err := base64.RawURLEncoding.DecodeString(s.RevokeDigest)
	if err != nil || len(stored) != sha256.Size || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		errorJSON(w, 403, "invalid revocation token")
		return
	}
	if err := os.Remove(a.path(id, ".bin")); err != nil && !errors.Is(err, os.ErrNotExist) {
		errorJSON(w, 500, "ciphertext deletion failed")
		return
	}
	if err := os.Remove(a.path(id, ".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		errorJSON(w, 500, "metadata deletion failed")
		return
	}
	delete(a.shares, id)
	a.size -= s.Size
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) download(w http.ResponseWriter, r *http.Request, id string) {
	// Prevent simple cross-origin GETs (links, images, and forms) from
	// exhausting download allowances without the user choosing to download.
	if r.Header.Get("X-GC-Client") != "web-v1" {
		errorJSON(w, http.StatusForbidden, "invalid client protocol")
		return
	}
	if !validID(id) {
		errorJSON(w, 404, "invalid share id")
		return
	}
	a.mu.Lock()
	a.clean()
	s, ok := a.shares[id]
	if !ok {
		a.mu.Unlock()
		errorJSON(w, 404, "share not found or expired")
		return
	}
	if s.Count >= s.Limit {
		a.mu.Unlock()
		errorJSON(w, 410, "download limit reached")
		return
	}
	f, err := os.Open(a.path(id, ".bin"))
	if err != nil {
		a.mu.Unlock()
		errorJSON(w, 500, "ciphertext unavailable")
		return
	}
	// Verify the persisted ciphertext before charging a retrieval attempt.
	// Pre-check only: as with all same-user local files, an attacker with
	// write access to the store can still race this check.
	if s.CipherSHA256 != "" {
		expected, decodeErr := base64.RawURLEncoding.DecodeString(s.CipherSHA256)
		hash := sha256.New()
		_, readErr := io.Copy(hash, f)
		if decodeErr != nil || len(expected) != sha256.Size || readErr != nil || subtle.ConstantTimeCompare(expected, hash.Sum(nil)) != 1 {
			f.Close()
			a.mu.Unlock()
			errorJSON(w, 500, "ciphertext integrity verification failed")
			return
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			a.mu.Unlock()
			errorJSON(w, 500, "ciphertext unavailable")
			return
		}
	}
	s.Count++
	if err = a.save(s); err != nil {
		s.Count--
		f.Close()
		a.mu.Unlock()
		errorJSON(w, 500, "storage error")
		return
	}
	size, meta := s.Size, s.Meta
	a.mu.Unlock()
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-GC-Meta", meta)
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.WriteHeader(200)
	_, _ = io.Copy(w, f)
}

// excludeFlags is intentionally opt-in. The same rules are applied to both
// inventories; an omitted -exclude flag does not silently hide any files.
type excludeFlags []string

func (e *excludeFlags) String() string { return strings.Join(*e, ",") }
func (e *excludeFlags) Set(pattern string) error {
	if err := syncplan.ValidateExclude(pattern); err != nil {
		return err
	}
	*e = append(*e, pattern)
	return nil
}

func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "loopback address")
	dir := flag.String("data", "", "private storage path")
	audit := flag.Bool("audit-store", false, "report storage integrity without changing files (JSON)")
	planSource := flag.String("plan-source", "", "read-only source folder for local comparison")
	planTarget := flag.String("plan-target", "", "read-only target folder for local comparison")
	exportInventory := flag.String("export-inventory", "", "save private, signed, read-only folder inventory outside -plan-source (requires -device-dir)")
	compareInventory := flag.String("compare-inventory", "", "read-only comparison against signed offline peer inventory (requires pinned -peer-fingerprint)")
	newInventoryChallenge := flag.Bool("new-inventory-challenge", false, "generate one fresh public 256-bit request challenge for an offline comparison")
	inventoryChallenge := flag.String("inventory-challenge", "", "bind signed -export-inventory to the comparing device's fresh 64-hex challenge")
	expectInventoryChallenge := flag.String("expect-inventory-challenge", "", "require an exact signed request challenge for -compare-inventory")
	challengeTicket := flag.String("challenge-ticket", "", "opt-in persistent one-use 0600 ticket: issue with -new-inventory-challenge or consume with -compare-inventory")
	newInventoryKey := flag.String("new-inventory-key", "", "standalone: generate a new private 0600 file with random 256-bit offline inventory encryption key; NEVER printed")
	inventoryKeyFile := flag.String("inventory-key-file", "", "opt-in AES-256-GCM encrypted offline inventory exchange; requires same confidential key file on both devices")
	var excludePatterns excludeFlags
	flag.Var(&excludePatterns, "exclude", "repeatable opt-in exclusion glob; e.g. *.tmp or secrets/**")
	applyAdditions := flag.Bool("apply-additions", false, "explicitly copy only source-only files without overwriting, deleting or resolving conflicts")
	applyBothAdditions := flag.Bool("apply-both-additions", false, "explicitly copy absent files in BOTH directions; refuse all divergent paths, no overwrites/deletions")
	captureBaseline := flag.String("capture-baseline", "", "save a new immutable 0600 baseline file outside both initially identical folders")
	baselineFile := flag.String("baseline", "", "read-only three-way planning against a previously captured baseline")
	watch := flag.Bool("watch", false, "foreground, read-only polling of local changes; emits changed JSON snapshots only")
	watchInterval := flag.Duration("watch-interval", 5*time.Second, "read-only polling interval for -watch, from 1s to 1h")
	syncAdditions := flag.Bool("sync-additions", false, "EXPLICIT foreground continuous local additions-only copies both ways; no deletes/overwrites; stops on conflict")
	syncInterval := flag.Duration("sync-interval", 15*time.Second, "continuous additions polling interval from 1s to 1h (default 15s)")
	syncState := flag.String("sync-state", "", "required durable private 0600 state file outside both folders for -sync-additions")
	initSyncState := flag.Bool("init-sync-state", false, "create new durable state only if both filtered folder inventories match")
	inspectSyncState := flag.Bool("inspect-sync-state", false, "read-only inspect validated durable sync state; never resume pending automatically")
	auditSyncState := flag.Bool("audit-sync-state", false, "read-only audit durable sync state against current folders; never clear an incomplete batch")
	checkRecovery := flag.Bool("check-pending-recovery", false, "read-only SHA-256 verification of an incomplete copy batch; never change files")
	finalizeRecovery := flag.Bool("finalize-completed-batch", false, "EXPLICITLY finalize an already-completed pending batch after complete hash checks; archive old journal; no file copies")
	receiveDir := flag.String("receive-dir", "", "start a one-time encrypted Send receiver; store exactly one file in this private directory")
	receiveAuditDir := flag.String("audit-receive-dir", "", "read-only inspect a private receiver directory for crash staging artifacts; never delete")
	receiveListen := flag.String("receive-listen", "127.0.0.1:8788", "address for manually started one-time Send receiver")
	receiveTimeout := flag.Duration("receive-timeout", 5*time.Minute, "maximum waiting time for one-file Nearby Send receiver (1s to 30m)")
	allowLAN := flag.Bool("allow-lan", false, "explicitly permit one-time Send receiver to listen on a private LAN interface")
	receiveTLS := flag.Bool("receive-tls", false, "protect one-time Nearby Send metadata with pairing-key-pinned TLS 1.3; mandatory outside loopback")
	sendFile := flag.String("send-file", "", "regular file to encrypt and transfer to a manually started Send receiver")
	sendURL := flag.String("send-url", "", "receiver URL with literal private IP and /send path (HTTPS pinned to pairing key; key read from stdin)")
	deviceDir := flag.String("device-dir", "", "private Ed25519 identity directory for device management or Nearby Send")
	deviceAction := flag.String("device-action", "", "device management: init, show, trust, list, untrust, rotation-proof, rotation-verify, or rotation-trust")
	rotationDir := flag.String("rotation-dir", "", "separate private directory containing the new identity for a public signed rotation proof")
	rotationProofPath := flag.String("rotation-proof", "", "path of untrusted public signed rotation proof JSON")
	newFingerprint := flag.String("new-fingerprint", "", "independently verified new sha256: fingerprint required before staging rotation trust")
	trustPublic := flag.String("trust-public", "", "untrusted base64url Ed25519 public key for explicit -device-action trust")
	peerFingerprint := flag.String("peer-fingerprint", "", "independently verified complete sha256: fingerprint; pins receiver when sending")
	requireSender := flag.String("require-sender-fingerprint", "", "receiver requires a trusted sender with this full sha256: fingerprint")
	mutualAuth := flag.Bool("mutual-auth", false, "sender requires pinned receiver AND receiver enforcement of its own signed sender identity")
	flag.Parse()
	lanMode := *receiveDir != "" || *sendFile != "" || *sendURL != "" || *allowLAN || *receiveTLS || *requireSender != "" || *mutualAuth
	if *newInventoryKey != "" {
		if *inventoryKeyFile != "" || *newInventoryChallenge || *inventoryChallenge != "" || *expectInventoryChallenge != "" || *challengeTicket != "" || *exportInventory != "" || *compareInventory != "" || *planSource != "" || *planTarget != "" || *deviceAction != "" || *deviceDir != "" || *peerFingerprint != "" || *trustPublic != "" || *rotationDir != "" || *rotationProofPath != "" || *newFingerprint != "" || *receiveAuditDir != "" || lanMode || *audit || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || len(excludePatterns) > 0 {
			log.Fatal("inventory encryption key generation is standalone")
		}
		if err := syncplan.NewPrivateInventoryKeyFile(*newInventoryKey); err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "offline-inventory-key-generated", "created": true}); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *inventoryKeyFile != "" && *exportInventory == "" && *compareInventory == "" {
		log.Fatal("-inventory-key-file applies only to -export-inventory or -compare-inventory")
	}
	if (*inventoryChallenge != "" && *exportInventory == "") || (*expectInventoryChallenge != "" && *compareInventory == "") || (*inventoryChallenge != "" && *expectInventoryChallenge != "") || (*challengeTicket != "" && !*newInventoryChallenge && *compareInventory == "") || (*challengeTicket != "" && *expectInventoryChallenge != "") {
		log.Fatal("inventory challenge flags are valid only for their matching export or compare operation")
	}
	if *newInventoryChallenge {
		if *exportInventory != "" || *compareInventory != "" || *planTarget != "" || *deviceAction != "" || *inventoryChallenge != "" || *expectInventoryChallenge != "" || *receiveAuditDir != "" || lanMode || *audit || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || *trustPublic != "" || *rotationDir != "" || *rotationProofPath != "" || *newFingerprint != "" {
			log.Fatal("inventory challenge generation cannot run other operations")
		}
		if *challengeTicket == "" && (*planSource != "" || *deviceDir != "" || *peerFingerprint != "" || len(excludePatterns) != 0) {
			log.Fatal("stateless challenge generation is standalone; use -challenge-ticket for persistent request mode")
		}
		if *challengeTicket != "" && (*planSource == "" || *deviceDir == "" || *peerFingerprint == "") {
			log.Fatal("one-use challenge generation requires -plan-source, -device-dir and pinned -peer-fingerprint")
		}
		var challenge string
		var err error
		if *challengeTicket == "" {
			challenge, err = syncplan.NewOfflineInventoryChallenge()
		} else {
			var pinned ed25519.PublicKey
			pinned, err = deviceid.Lookup(*deviceDir, *peerFingerprint)
			if err == nil {
				challenge, err = syncplan.IssueOneUseInventoryChallenge(*challengeTicket, *planSource, *peerFingerprint, excludePatterns, pinned)
			}
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "offline-inventory-challenge", "challenge": challenge, "oneUseTicketIssued": *challengeTicket != ""}); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *receiveAuditDir != "" {
		if *exportInventory != "" || *compareInventory != "" || lanMode || *deviceAction != "" || *deviceDir != "" || *peerFingerprint != "" || *trustPublic != "" || *rotationDir != "" || *rotationProofPath != "" || *newFingerprint != "" || *audit || *planSource != "" || *planTarget != "" || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || len(excludePatterns) > 0 {
			log.Fatal("receiver-directory audit is read-only and cannot be combined with any other mode")
		}
		report, err := lansend.AuditReceiverDirectory(*receiveAuditDir)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			log.Fatal(err)
		}
		if report.StageResidueCount > 0 {
			os.Exit(2)
		}
		return
	}
	if *deviceAction != "" {
		if *deviceDir == "" || *exportInventory != "" || *compareInventory != "" || lanMode || *audit || *planSource != "" || *planTarget != "" || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || len(excludePatterns) > 0 {
			log.Fatal("device management requires -device-dir and cannot be combined with Nearby Send, audit or Sync planning")
		}
		if (*rotationDir != "" || *rotationProofPath != "" || *newFingerprint != "") &&
			*deviceAction != "rotation-proof" && *deviceAction != "rotation-verify" && *deviceAction != "rotation-trust" {
			log.Fatal("rotation arguments require a rotation device action")
		}
		var result any
		var err error
		switch *deviceAction {
		case "init":
			if *trustPublic != "" || *peerFingerprint != "" {
				log.Fatal("init does not accept peer trust arguments")
			}
			result, err = deviceid.Initialize(*deviceDir)
		case "show":
			if *trustPublic != "" || *peerFingerprint != "" {
				log.Fatal("show does not accept peer trust arguments")
			}
			var id *deviceid.Identity
			id, err = deviceid.Load(*deviceDir)
			if err == nil {
				result = id.Public()
			}
		case "trust":
			if *trustPublic == "" || *peerFingerprint == "" {
				log.Fatal("trust requires -trust-public and independently verified -peer-fingerprint")
			}
			result, err = deviceid.Trust(*deviceDir, *trustPublic, *peerFingerprint)
		case "untrust":
			if *trustPublic != "" || *peerFingerprint == "" {
				log.Fatal("untrust requires -peer-fingerprint without -trust-public")
			}
			err = deviceid.Untrust(*deviceDir, *peerFingerprint)
			result = map[string]string{"status": "untrusted", "fingerprint": *peerFingerprint}
		case "list":
			if *trustPublic != "" || *peerFingerprint != "" {
				log.Fatal("list does not accept peer trust arguments")
			}
			result, err = deviceid.List(*deviceDir)
		case "rotation-proof":
			if *rotationDir == "" || *rotationProofPath != "" || *newFingerprint != "" || *trustPublic != "" || *peerFingerprint != "" {
				log.Fatal("rotation-proof requires -rotation-dir and no trust or other rotation arguments")
			}
			var previous, replacement *deviceid.Identity
			previous, err = deviceid.Load(*deviceDir)
			if err == nil {
				replacement, err = deviceid.Load(*rotationDir)
			}
			if err == nil {
				result, err = deviceid.MakeRotationProof(previous, replacement)
			}
		case "rotation-verify", "rotation-trust":
			if *rotationProofPath == "" || *peerFingerprint == "" || *rotationDir != "" || *trustPublic != "" || (*deviceAction == "rotation-verify" && *newFingerprint != "") || (*deviceAction == "rotation-trust" && *newFingerprint == "") {
				log.Fatal("rotation verification requires a trusted old -peer-fingerprint, -rotation-proof and (only for rotation-trust) independently verified -new-fingerprint")
			}
			var proof deviceid.RotationProof
			proof, err = deviceid.ReadRotationProof(*rotationProofPath)
			if err == nil {
				if *deviceAction == "rotation-verify" {
					result, err = deviceid.VerifyPinnedRotation(*deviceDir, *peerFingerprint, proof)
				} else {
					result, err = deviceid.TrustRotation(*deviceDir, *peerFingerprint, proof, *newFingerprint)
				}
			}
		default:
			log.Fatal("unknown -device-action (init, show, trust, list, untrust, rotation-proof, rotation-verify, rotation-trust)")
		}
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *trustPublic != "" || *rotationDir != "" || *rotationProofPath != "" || *newFingerprint != "" {
		log.Fatal("trust and rotation flags require an explicit -device-action")
	}
	if *exportInventory != "" || *compareInventory != "" {
		if (*exportInventory != "" && *compareInventory != "") || *planSource == "" || *planTarget != "" || *deviceDir == "" || *deviceAction != "" || lanMode || *receiveAuditDir != "" || *audit || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery {
			log.Fatal("offline inventory mode requires -plan-source and -device-dir; cannot combine with another operation")
		}
		if *exportInventory != "" {
			if *challengeTicket != "" {
				log.Fatal("-challenge-ticket is for generation and comparison, not export")
			}
			if *peerFingerprint != "" {
				log.Fatal("export must not specify a peer fingerprint")
			}
			own, err := deviceid.Load(*deviceDir)
			if err != nil {
				log.Fatal(err)
			}
			var signed syncplan.OfflineInventory
			if *inventoryKeyFile != "" {
				signed, err = syncplan.ExportEncryptedChallengedOfflineInventory(*planSource, *exportInventory, excludePatterns, own, *inventoryChallenge, *inventoryKeyFile)
			} else {
				signed, err = syncplan.ExportChallengedOfflineInventory(*planSource, *exportInventory, excludePatterns, own, *inventoryChallenge)
			}
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "signed-inventory-export", "fingerprint": signed.Fingerprint, "capturedAt": signed.CapturedAt, "files": len(signed.Files)}); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *peerFingerprint == "" {
			log.Fatal("offline comparison requires independently trusted -peer-fingerprint")
		}
		pinned, err := deviceid.Lookup(*deviceDir, *peerFingerprint)
		if err != nil {
			log.Fatal("offline inventory peer is not trusted: ", err)
		}
		var plan syncplan.OfflineComparison
		if *challengeTicket != "" {
			if *inventoryKeyFile != "" {
				plan, err = syncplan.CompareWithEncryptedOneUseInventoryTicket(*planSource, excludePatterns, *compareInventory, *peerFingerprint, pinned, *challengeTicket, *inventoryKeyFile)
			} else {
				plan, err = syncplan.CompareWithOneUseInventoryTicket(*planSource, excludePatterns, *compareInventory, *peerFingerprint, pinned, *challengeTicket)
			}
		} else if *inventoryKeyFile != "" {
			plan, err = syncplan.CompareVerifiedEncryptedOfflineInventory(*planSource, excludePatterns, *compareInventory, *peerFingerprint, pinned, *expectInventoryChallenge, *inventoryKeyFile)
		} else if *expectInventoryChallenge != "" {
			plan, err = syncplan.CompareVerifiedOfflineInventoryWithChallenge(*planSource, excludePatterns, *compareInventory, *peerFingerprint, pinned, *expectInventoryChallenge)
		} else {
			plan, err = syncplan.CompareVerifiedOfflineInventory(*planSource, excludePatterns, *compareInventory, *peerFingerprint, pinned)
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
			log.Fatal(err)
		}
		return
	}
	if !lanMode && (*deviceDir != "" || *peerFingerprint != "") {
		log.Fatal("-device-dir and -peer-fingerprint require device management or Nearby Send")
	}
	if lanMode {
		if *audit || *planSource != "" || *planTarget != "" || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || len(excludePatterns) > 0 {
			log.Fatal("Nearby Send cannot be combined with store audit or folder planning")
		}
		if *receiveDir != "" {
			if *mutualAuth {
				log.Fatal("-mutual-auth applies only to sender")
			}
			if *peerFingerprint != "" {
				log.Fatal("-peer-fingerprint is a sender-only option")
			}
			if *sendFile != "" || *sendURL != "" {
				log.Fatal("choose either receiver or sender")
			}
			if *receiveTimeout < time.Second || *receiveTimeout > 30*time.Minute {
				log.Fatal("-receive-timeout must be between 1s and 30m")
			}
			signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			ctx, cancel := context.WithTimeout(signalCtx, *receiveTimeout)
			defer cancel()
			var device *deviceid.Identity
			if *deviceDir != "" {
				var e error
				device, e = deviceid.Load(*deviceDir)
				if e != nil {
					log.Fatal(e)
				}
			}
			var trustedSender ed25519.PublicKey
			if *requireSender != "" {
				if *deviceDir == "" {
					log.Fatal("receiver -require-sender-fingerprint requires -device-dir")
				}
				var e error
				trustedSender, e = deviceid.Lookup(*deviceDir, *requireSender)
				if e != nil {
					log.Fatal("required sender is not trusted: ", e)
				}
			}
			receipt, err := lansend.ReceiveOnceWithTransport(ctx, *receiveListen, *receiveDir, *allowLAN, *receiveTLS, os.Stdout, device, trustedSender)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *requireSender != "" {
			log.Fatal("-require-sender-fingerprint is a receiver-only option")
		}
		if *sendFile == "" || *sendURL == "" || *allowLAN || *receiveTLS {
			log.Fatal("sender requires -send-file and -send-url; -allow-lan and -receive-tls apply only to receivers")
		}
		if (*deviceDir == "") != (*peerFingerprint == "") {
			log.Fatal("sender device identity proof requires both -device-dir and -peer-fingerprint; no silent fallback")
		}
		if *mutualAuth && *deviceDir == "" {
			log.Fatal("mutual identity proof requires local identity and pinned receiver")
		}

		reader := bufio.NewScanner(os.Stdin)
		reader.Buffer(make([]byte, 0, 64), 256)
		if !reader.Scan() {
			if err := reader.Err(); err != nil {
				log.Fatal("cannot read pairing key: ", err)
			}
			log.Fatal("missing pairing key on stdin")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var receipt lansend.Receipt
		var err error
		if *deviceDir != "" {
			pub, e := deviceid.Lookup(*deviceDir, *peerFingerprint)
			if e != nil {
				log.Fatal("receiver is not trusted: ", e)
			}
			if *mutualAuth {
				own, e := deviceid.Load(*deviceDir)
				if e != nil {
					log.Fatal(e)
				}
				receipt, err = lansend.SendFileWithMutualAuth(ctx, *sendURL, reader.Text(), *sendFile, pub, own)
			} else {
				receipt, err = lansend.SendFileWithPinnedReceiver(ctx, *sendURL, reader.Text(), *sendFile, pub)
			}
		} else {
			receipt, err = lansend.SendFile(ctx, *sendURL, reader.Text(), *sendFile)
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
			log.Fatal(err)
		}
		return
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("only loopback listen addresses allowed")
	}
	if *dir == "" {
		cfg, e := os.UserConfigDir()
		if e != nil {
			log.Fatal(e)
		}
		*dir = filepath.Join(cfg, "goreecloud-sync", "shares")
	}
	if *audit && (*planSource != "" || *planTarget != "" || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || len(excludePatterns) > 0) {
		log.Fatal("choose either store audit or folder comparison")
	}
	if *planSource != "" || *planTarget != "" || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "" || *watch || *watchInterval != 5*time.Second || *syncAdditions || *syncInterval != 15*time.Second || *syncState != "" || *initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery || len(excludePatterns) > 0 {
		if *planSource == "" || *planTarget == "" {
			log.Fatal("both -plan-source and -plan-target are required")
		}
		if (*captureBaseline != "" && *baselineFile != "") || (*applyAdditions && (*captureBaseline != "" || *baselineFile != "" || *watch || *applyBothAdditions)) || (*applyBothAdditions && (*captureBaseline != "" || *baselineFile != "" || *watch)) || (*captureBaseline != "" && *watch) || (*syncAdditions && (*watch || *applyAdditions || *applyBothAdditions || *captureBaseline != "" || *baselineFile != "")) {
			log.Fatal("choose only one of -apply-additions, -capture-baseline, or -baseline")
		}
		stateOperations := 0
		for _, enabled := range []bool{*initSyncState, *inspectSyncState, *auditSyncState, *syncAdditions, *checkRecovery, *finalizeRecovery} {
			if enabled {
				stateOperations++
			}
		}
		if stateOperations > 1 {
			log.Fatal("choose only one durable state operation at a time")
		}
		if *syncState != "" && stateOperations == 0 {
			log.Fatal("-sync-state requires an explicit durable state operation")
		}
		if stateOperations > 0 && *syncState == "" {
			log.Fatal("durable Sync requires an explicit -sync-state path")
		}
		if (*initSyncState || *inspectSyncState || *auditSyncState || *checkRecovery || *finalizeRecovery) && (*captureBaseline != "" || *baselineFile != "" || *watch || *applyAdditions || *applyBothAdditions) {
			log.Fatal("durable state initialization/inspection cannot be combined with other Sync modes")
		}
		if !*watch && *watchInterval != 5*time.Second {
			log.Fatal("-watch-interval requires -watch")
		}
		if !*syncAdditions && *syncInterval != 15*time.Second {
			log.Fatal("-sync-interval requires -sync-additions")
		}
		if *initSyncState {
			state, err := syncplan.InitDurableState(*planSource, *planTarget, *syncState, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "sync-state-initialized", "version": state.Version, "phase": state.Phase, "generation": state.Generation, "files": len(state.Files)}); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *inspectSyncState {
			state, err := syncplan.ValidateDurableState(*planSource, *planTarget, *syncState, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "sync-state-inspection", "version": state.Version, "phase": state.Phase, "generation": state.Generation, "files": len(state.Files), "pending": state.Pending, "checksum": state.Checksum}); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *auditSyncState {
			report, err := syncplan.AuditDurableState(*planSource, *planTarget, *syncState, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *checkRecovery {
			report, err := syncplan.ReviewDurableRecovery(*planSource, *planTarget, *syncState, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *finalizeRecovery {
			result, err := syncplan.FinalizeCompletedDurableBatch(*planSource, *planTarget, *syncState, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *syncAdditions {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			encoder := json.NewEncoder(os.Stdout)
			err := syncplan.RunDurableContinuousAdditions(ctx, *planSource, *planTarget, excludePatterns, *syncInterval, *syncState, func(event syncplan.ContinuousAdditionsEvent) error {
				return encoder.Encode(event)
			})
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		if *watch {
			if *watchInterval < time.Second || *watchInterval > time.Hour {
				log.Fatal("-watch-interval must be between 1s and 1h")
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			encoder := json.NewEncoder(os.Stdout)
			err := syncplan.WatchChanges(ctx, *planSource, *planTarget, *baselineFile, excludePatterns, *watchInterval, func(event syncplan.WatchEvent) error {
				return encoder.Encode(event)
			})
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		if *captureBaseline != "" {
			baseline, err := syncplan.CaptureBaseline(*planSource, *planTarget, *captureBaseline, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "baseline-captured", "files": len(baseline.Files), "version": baseline.Version, "excludes": baseline.Excludes}); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *baselineFile != "" {
			plan, err := syncplan.CompareHistorical(*planSource, *planTarget, *baselineFile, excludePatterns)
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
				log.Fatal(err)
			}
			return
		}
		if *applyBothAdditions {
			result, err := syncplan.ApplyBidirectionalAdditionsFiltered(*planSource, *planTarget, excludePatterns)
			if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
				log.Fatal(encodeErr)
			}
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		if *applyAdditions {
			result, err := syncplan.ApplyAdditionsFiltered(*planSource, *planTarget, excludePatterns)
			if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
				log.Fatal(encodeErr)
			}
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		plan, err := syncplan.CompareFiltered(*planSource, *planTarget, excludePatterns)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *audit {
		report, err := auditStore(*dir, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			log.Fatal(err)
		}
		if report.Errors > 0 {
			os.Exit(2)
		}
		return
	}
	a, err := newApp(*dir)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go a.runJanitor(ctx, time.Minute)
	server := &http.Server{Addr: *addr, Handler: a, ReadTimeout: 60 * time.Second, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("GoreeCloud Sync sharing preview: http://%s", *addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
