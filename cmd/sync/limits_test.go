package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func validUploadRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/shares", bytes.NewReader(append([]byte("GCS1"), make([]byte, 28)...)))
	r.Host = "127.0.0.1:8787"
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("X-GC-Client", "web-v1")
	r.Header.Set("X-GC-Meta", base64.RawURLEncoding.EncodeToString(make([]byte, 28)))
	digest := sha256.Sum256([]byte("01234567890123456789012345678901"))
	r.Header.Set("X-GC-Revoke-Digest", base64.RawURLEncoding.EncodeToString(digest[:]))
	return r
}

func TestStoredShareCountLimitBeforeWriting(t *testing.T) {
	a, dir := testApp(t)
	expires := time.Now().Add(time.Hour)
	for i := 0; i < maxShareRecords; i++ {
		id := fmt.Sprintf("%032x", i)
		a.shares[id] = &share{ID: id, Expires: expires, Limit: 1, Size: 32}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, validUploadRequest())
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d %s", w.Code, w.Body.String())
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("refused upload wrote files: %+v %v", files, err)
	}
	// A record removed by the normal expiration cleanup allows a new upload.
	a.shares[fmt.Sprintf("%032x", 0)].Expires = time.Now().Add(-time.Second)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, validUploadRequest())
	if w.Code != http.StatusCreated {
		t.Fatalf("expired slot not reclaimed: %d %s", w.Code, w.Body.String())
	}
}

func TestLocalUploadAdmissionWindow(t *testing.T) {
	a, dir := testApp(t)
	clock := time.Now()
	a.now = func() time.Time { return clock }
	a.uploadWindow = clock
	a.uploadCount = maxUploadAttemptsPerMinute
	w := httptest.NewRecorder()
	a.ServeHTTP(w, validUploadRequest())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d %s", w.Code, w.Body.String())
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("rate-limited upload wrote files: %+v %v", files, err)
	}
	clock = clock.Add(time.Minute)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, validUploadRequest())
	if w.Code != http.StatusCreated || a.uploadCount != 1 {
		t.Fatalf("window did not reset: %d count=%d", w.Code, a.uploadCount)
	}
	// Even syntactically valid but corrupt ciphertext consumes an attempt.
	invalid := validUploadRequest()
	invalid.Body = io.NopCloser(bytes.NewReader([]byte("not a valid envelope!")))
	w = httptest.NewRecorder()
	a.ServeHTTP(w, invalid)
	if w.Code == http.StatusCreated || a.uploadCount != 2 {
		t.Fatalf("invalid ciphertext did not count as an attempt: %d count=%d", w.Code, a.uploadCount)
	}
}
