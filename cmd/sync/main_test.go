package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testApp(t *testing.T) (*app, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := newApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	return a, dir
}
func upload(t *testing.T, a *app, count string) string {
	t.Helper()
	body := append([]byte("GCS1"), make([]byte, 28)...)
	r := httptest.NewRequest("POST", "/api/shares", bytes.NewReader(body))
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-GC-Client", "web-v1")
	r.Header.Set("X-GC-Meta", base64.RawURLEncoding.EncodeToString(make([]byte, 28)))
	secretHash := sha256.Sum256([]byte("01234567890123456789012345678901"))
	r.Header.Set("X-GC-Revoke-Digest", base64.RawURLEncoding.EncodeToString(secretHash[:]))
	if count != "" {
		r.Header.Set("X-GC-Downloads", count)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}
func fetch(a *app, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", path, nil)
	r.Host = "127.0.0.1:8787"
	if len(path) >= 12 && path[:12] == "/api/shares/" {
		r.Header.Set("X-GC-Client", "web-v1")
	}
	a.ServeHTTP(w, r)
	return w
}
func TestUploadDownloadLimit(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "2")
	if !validID(id) {
		t.Fatal("invalid ID")
	}
	for i := 0; i < 2; i++ {
		w := fetch(a, "/api/shares/"+id)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), append([]byte("GCS1"), make([]byte, 28)...)) {
			t.Fatalf("download %d: %d", i, w.Code)
		}
		if w.Header().Get("X-GC-Meta") == "" {
			t.Fatal("missing encrypted metadata")
		}
	}
	if w := fetch(a, "/api/shares/"+id); w.Code != 410 {
		t.Fatalf("limit: %d", w.Code)
	}
	fi, err := os.Stat(filepath.Join(dir, id+".json"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("metadata not private")
	}
}
func TestRestartExpiry(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "")
	next, err := newApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if w := fetch(next, "/api/shares/"+id); w.Code != 200 {
		t.Fatal("share not reloaded")
	}
	next.now = func() time.Time { return time.Now().Add(2 * 24 * time.Hour) }
	if w := fetch(next, "/api/shares/"+id); w.Code != 404 {
		t.Fatalf("expired: %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".bin")); !os.IsNotExist(err) {
		t.Fatal("expired blob not removed")
	}
}
func TestValidation(t *testing.T) {
	a, _ := testApp(t)
	if w := fetch(a, "/api/shares/../../etc/passwd"); w.Code == 200 {
		t.Fatal("unsafe path")
	}
	r := httptest.NewRequest(http.MethodPost, "/api/shares", bytes.NewReader(append([]byte("GCS1"), make([]byte, 28)...)))
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Origin", "https://evil.invalid")
	r.Header.Set("X-GC-Client", "web-v1")
	r.Header.Set("X-GC-Meta", base64.RawURLEncoding.EncodeToString(make([]byte, 28)))
	secretHash := sha256.Sum256([]byte("01234567890123456789012345678901"))
	r.Header.Set("X-GC-Revoke-Digest", base64.RawURLEncoding.EncodeToString(secretHash[:]))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-origin %d", w.Code)
	}
}
func TestAssets(t *testing.T) {
	a, _ := testApp(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/health"} {
		w := fetch(a, path)
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}

func TestRejectDNSRebindingAndForeignOrigins(t *testing.T) {
	a, _ := testApp(t)
	tests := []struct {
		host, origin, path, want string
		status                   int
	}{
		{"attacker.example:8787", "", "/", "host", http.StatusForbidden},
		{"localhost:8787", "", "/app.js", "hostname", http.StatusForbidden},
		{"127.0.0.1:8787", "", "/", "allow local literal", http.StatusOK},
		{"[::1]:8787", "", "/", "IPv6 loopback", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d expected=%d", w.Code, tc.status)
			}
		})
	}
	for _, origin := range []string{"", "null", "http://attacker.example:8787"} {
		r := httptest.NewRequest("POST", "/api/shares", bytes.NewReader(append([]byte("GCS1"), make([]byte, 28)...)))
		r.Host = "127.0.0.1:8787"
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-GC-Client", "web-v1")
		r.Header.Set("X-GC-Meta", base64.RawURLEncoding.EncodeToString(make([]byte, 28)))
		secretHash := sha256.Sum256([]byte("01234567890123456789012345678901"))
		r.Header.Set("X-GC-Revoke-Digest", base64.RawURLEncoding.EncodeToString(secretHash[:]))
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("origin=%q status=%d", origin, w.Code)
		}
	}
}
func TestPreventDownloadAllowanceExhaustion(t *testing.T) {
	a, _ := testApp(t)
	id := upload(t, a, "1")
	r := httptest.NewRequest("GET", "/api/shares/"+id, nil)
	r.Host = "127.0.0.1:8787"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("untrusted GET: %d", w.Code)
	}
	r = httptest.NewRequest("GET", "/api/shares/"+id, nil)
	r.Host = "127.0.0.1:8787"
	r.Header.Set("X-GC-Client", "web-v1")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-site GET: %d", w.Code)
	}
	if w := fetch(a, "/api/shares/"+id); w.Code != 200 {
		t.Fatalf("first trusted download: %d", w.Code)
	}
	if w := fetch(a, "/api/shares/"+id); w.Code != 410 {
		t.Fatalf("allowance not enforced: %d", w.Code)
	}
}
func TestUploadConcurrencyAndMediaType(t *testing.T) {
	a, _ := testApp(t)
	for i := 0; i < cap(a.uploads); i++ {
		a.uploads <- struct{}{}
	}
	r := httptest.NewRequest("POST", "/api/shares", bytes.NewReader(append([]byte("GCS1"), make([]byte, 28)...)))
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("X-GC-Client", "web-v1")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("overloaded: %d", w.Code)
	}
	for i := 0; i < cap(a.uploads); i++ {
		<-a.uploads
	}
	r = httptest.NewRequest("POST", "/api/shares", strings.NewReader("test"))
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatalf("media type: %d", w.Code)
	}
}
func TestJanitorPrunesWithoutNewRequests(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "")
	a.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.runJanitor(ctx, time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		_, err := os.Stat(filepath.Join(dir, id+".bin"))
		if os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("janitor did not prune")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRevokeRequiresOwnerSecret(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "5")
	secret := []byte("01234567890123456789012345678901")
	revoke := func(token string, origin string) int {
		r := httptest.NewRequest("POST", "/api/shares/"+id+"/revoke", nil)
		r.Host = "127.0.0.1:8787"
		r.Header.Set("Origin", origin)
		r.Header.Set("X-GC-Client", "web-v1")
		r.Header.Set("X-GC-Revoke-Token", token)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Code
	}
	valid := base64.RawURLEncoding.EncodeToString(secret)
	if status := revoke(valid, "http://not-local.invalid"); status != 403 {
		t.Fatalf("cross-origin revoke: %d", status)
	}
	if status := revoke(base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "http://127.0.0.1:8787"); status != 403 {
		t.Fatalf("wrong token: %d", status)
	}
	if status := revoke(valid, "http://127.0.0.1:8787"); status != 204 {
		t.Fatalf("valid revoke: %d", status)
	}
	if status := revoke(valid, "http://127.0.0.1:8787"); status != 404 {
		t.Fatalf("repeat revoke: %d", status)
	}
	if w := fetch(a, "/api/shares/"+id); w.Code != 404 {
		t.Fatalf("revoked still downloadable: %d", w.Code)
	}
	for _, ext := range []string{".bin", ".json"} {
		if _, err := os.Stat(filepath.Join(dir, id+ext)); !os.IsNotExist(err) {
			t.Fatalf("revoked file persists: %s", ext)
		}
	}
}

// A surge of competing downloads must never exceed a share's retrieval limit.
func TestConcurrentDownloadsHonorLimit(t *testing.T) {
	a, _ := testApp(t)
	id := upload(t, a, "5")
	var success, limited, other atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := fetch(a, "/api/shares/"+id)
			switch w.Code {
			case 200:
				success.Add(1)
			case 410:
				limited.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 5 || limited.Load() != 55 || other.Load() != 0 {
		t.Fatalf("success=%d limit=%d unexpected=%d", success.Load(), limited.Load(), other.Load())
	}
}
func TestStorageQuotaRejectsExcessUpload(t *testing.T) {
	a, dir := testApp(t)
	a.size = maxStorage
	body := append([]byte("GCS1"), make([]byte, 28)...)
	r := httptest.NewRequest("POST", "/api/shares", bytes.NewReader(body))
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-GC-Client", "web-v1")
	r.Header.Set("X-GC-Meta", base64.RawURLEncoding.EncodeToString(make([]byte, 28)))
	digest := sha256.Sum256([]byte("01234567890123456789012345678901"))
	r.Header.Set("X-GC-Revoke-Digest", base64.RawURLEncoding.EncodeToString(digest[:]))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("quota status: %d", w.Code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "upload-") {
			t.Fatalf("temporary data leaked: %s", entry.Name())
		}
	}
}

func TestWebControlsMatchEncryptedSharingImplementation(t *testing.T) {
	page, err := web.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := web.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"send", "file", "result", "url", "copy", "revoke", "download", "receiver", "ttl", "downloads", "status"} {
		if !bytes.Contains(page, []byte("id=\""+id+"\"")) {
			t.Errorf("missing HTML element for JS control: %s", id)
		}
	}
	for _, token := range []string{"X-GC-Revoke-Digest", "X-GC-Revoke-Token", "X-GC-Client"} {
		if !bytes.Contains(script, []byte(token)) {
			t.Errorf("missing protocol header in client JS: %s", token)
		}
	}
}

func TestRestartCleansOnlyStaleAppTempFiles(t *testing.T) {
	a, dir := testApp(t)
	_ = a
	old := filepath.Join(dir, "upload-old-ciphertext")
	recent := filepath.Join(dir, "upload-recent")
	keep := filepath.Join(dir, "notes.txt")
	for _, p := range []string{old, recent, keep} {
		if err := os.WriteFile(p, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(old, t0, t0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keep, t0, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("stale app temporary ciphertext persists: %v", err)
	}
	for _, p := range []string{recent, keep} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("file unexpectedly removed: %s %v", p, err)
		}
	}
}
