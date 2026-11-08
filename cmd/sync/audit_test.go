package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCiphertextChecksumStopsDamagedDownloadWithoutSpendingAllowance(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "1")
	before, err := os.ReadFile(a.path(id, ".bin"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := os.ReadFile(a.path(id, ".json"))
	if err != nil {
		t.Fatal(err)
	}
	var s share
	if err := json.Unmarshal(meta, &s); err != nil {
		t.Fatal(err)
	}
	checksum, err := base64.RawURLEncoding.DecodeString(s.CipherSHA256)
	if err != nil || len(checksum) != 32 {
		t.Fatalf("persisted checksum invalid: %v", err)
	}
	damaged := bytes.Clone(before)
	damaged[len(damaged)-1] ^= 0x40
	if err := os.WriteFile(a.path(id, ".bin"), damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if w := fetch(a, "/api/shares/"+id); w.Code != 500 {
		t.Fatalf("corrupted content returned status %d", w.Code)
	}
	if a.shares[id].Count != 0 {
		t.Fatal("corrupt download spent retrieval allowance")
	}
	report, err := auditStore(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Errors != 1 || report.Findings[0].Code != "ciphertext-checksum-mismatch" {
		t.Fatalf("audit missed corruption: %+v", report)
	}
	// Audit must not erase or silently rewrite bad content.
	stillDamaged, err := os.ReadFile(a.path(id, ".bin"))
	if err != nil || !bytes.Equal(stillDamaged, damaged) {
		t.Fatal("audit modified corrupt ciphertext")
	}
	if err := os.WriteFile(a.path(id, ".bin"), before, 0600); err != nil {
		t.Fatal(err)
	}
	if w := fetch(a, "/api/shares/"+id); w.Code != 200 {
		t.Fatalf("restored content unavailable: %d", w.Code)
	}
}

func TestAuditIdentifiesOrphansAndInconsistentRecordsWithoutMutations(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "5")
	good, err := auditStore(dir, time.Now())
	if err != nil || good.Errors != 0 || good.Warnings != 0 || good.ActiveShares != 1 {
		t.Fatalf("healthy store not clean: %+v err=%v", good, err)
	}
	orphan := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(filepath.Join(dir, orphan+".bin"), []byte("synthetic ciphertext orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	broken := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := os.WriteFile(filepath.Join(dir, broken+".json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	missing := "cccccccccccccccccccccccccccccccc"
	record := *a.shares[id]
	record.ID = missing
	b, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(dir, missing+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := auditStore(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range report.Findings {
		found[f.Code] = true
	}
	if !found["orphan-ciphertext"] || !found["malformed-metadata"] || !found["missing-or-invalid-ciphertext"] {
		t.Fatalf("missing diagnostics: %+v", report)
	}
	if report.Errors != 2 || report.Warnings != 1 || report.ActiveShares != 1 {
		t.Fatalf("unexpected summary: %+v", report)
	}
	for _, p := range []string{orphan + ".bin", broken + ".json", missing + ".json"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("audit removed %s: %v", p, err)
		}
	}
}

func TestAuditLegacyAndExpiredState(t *testing.T) {
	a, dir := testApp(t)
	id := upload(t, a, "2")
	s := a.shares[id]
	s.CipherSHA256 = ""
	if err := a.save(s); err != nil {
		t.Fatal(err)
	}
	report, err := auditStore(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Errors != 0 || report.Warnings != 1 || report.Findings[0].Code != "legacy-share-without-checksum" {
		t.Fatalf("legacy compatibility: %+v", report)
	}
	if fetch(a, "/api/shares/"+id).Code != 200 {
		t.Fatal("legacy share unexpectedly blocked")
	}
	s.Expires = time.Now().Add(-time.Hour)
	if err := a.save(s); err != nil {
		t.Fatal(err)
	}
	report, err = auditStore(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.ExpiredShares != 1 || report.Findings[0].Code != "expired-share-pending-cleanup" {
		t.Fatalf("expired status: %+v", report)
	}
}

func TestAuditRejectsUntrustedDirectory(t *testing.T) {
	_, dir := testApp(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := auditStore(dir, time.Now()); err == nil {
		t.Fatal("audit should reject public storage dir")
	}
	if _, err := auditStore(filepath.Join(dir, "missing"), time.Now()); err == nil {
		t.Fatal("audit should report missing storage")
	}
}

func TestStorageQuotaAccountsForOrphanedCiphertext(t *testing.T) {
	a, dir := testApp(t)
	orphan := filepath.Join(dir, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.bin")
	f, err := os.OpenFile(orphan, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxStorage); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// An orphaned blob cannot bypass the quota just because a.shares did
	// not load it into the active index.
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
	if w.Code != 507 {
		t.Fatalf("orphaned ciphertext should consume quota, received %d", w.Code)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("quota calculation unexpectedly erased orphan: %v", err)
	}
}
