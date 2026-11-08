package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// auditResult is a non-destructive snapshot of the local ciphertext store.
// Findings contain opaque random IDs only; no filenames, keys, or plaintext.
type auditResult struct {
	ActiveShares  int            `json:"activeShares"`
	ExpiredShares int            `json:"expiredShares"`
	StoredBytes   int64          `json:"storedBytes"`
	Errors        int            `json:"errors"`
	Warnings      int            `json:"warnings"`
	Findings      []auditFinding `json:"findings"`
}
type auditFinding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	ID       string `json:"id,omitempty"`
}

// auditStore never creates, modifies, or removes a file. A caller can run
// this before manually planning recovery of orphaned or corrupted content.
func auditStore(dir string, now time.Time) (auditResult, error) {
	report := auditResult{Findings: []auditFinding{}}
	stat, err := os.Lstat(dir)
	if err != nil {
		return report, err
	}
	if !stat.IsDir() || stat.Mode().Perm()&0077 != 0 {
		return report, fmt.Errorf("storage directory must be private (0700)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return report, err
	}
	byName := map[string]os.DirEntry{}
	for _, item := range entries {
		byName[item.Name()] = item
	}
	record := func(severity, code, id string) {
		report.Findings = append(report.Findings, auditFinding{Severity: severity, Code: code, ID: id})
		if severity == "error" {
			report.Errors++
		} else {
			report.Warnings++
		}
	}
	for _, item := range entries {
		name := item.Name()
		if strings.HasPrefix(name, "upload-") || strings.HasPrefix(name, "meta-") {
			if item.Type().IsRegular() {
				info, e := item.Info()
				if e != nil {
					record("error", "unreadable-temp", "")
				} else if info.ModTime().Before(now.Add(-time.Hour)) {
					record("warning", "stale-temporary-file", "")
				}
			}
			continue
		}
		if strings.HasSuffix(name, ".bin") {
			id := strings.TrimSuffix(name, ".bin")
			if validID(id) {
				if _, exists := byName[id+".json"]; !exists {
					record("warning", "orphan-ciphertext", id)
				}
			}
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !validID(id) {
			continue
		}
		if !item.Type().IsRegular() {
			record("error", "invalid-metadata-file", id)
			continue
		}
		fi, err := item.Info()
		if err != nil || fi.Size() > 16<<10 {
			record("error", "unreadable-metadata", id)
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			record("error", "unreadable-metadata", id)
			continue
		}
		var s share
		if json.Unmarshal(b, &s) != nil || s.ID != id || s.Size < 32 || s.Size > maxCiphertext || s.Limit < 1 || s.Limit > 5 || s.Count < 0 || s.Count > s.Limit {
			record("error", "malformed-metadata", id)
			continue
		}
		blob, exists := byName[id+".bin"]
		if !exists || !blob.Type().IsRegular() {
			record("error", "missing-or-invalid-ciphertext", id)
			continue
		}
		info, err := blob.Info()
		if err != nil || info.Size() != s.Size {
			record("error", "ciphertext-size-mismatch", id)
			continue
		}
		report.StoredBytes += s.Size
		if !now.Before(s.Expires) {
			report.ExpiredShares++
			record("warning", "expired-share-pending-cleanup", id)
			continue
		}
		report.ActiveShares++
		if s.CipherSHA256 == "" {
			record("warning", "legacy-share-without-checksum", id)
			continue
		}
		expected, err := base64.RawURLEncoding.DecodeString(s.CipherSHA256)
		if err != nil || len(expected) != sha256.Size {
			record("error", "invalid-ciphertext-checksum", id)
			continue
		}
		f, err := os.Open(filepath.Join(dir, id+".bin"))
		if err != nil {
			record("error", "ciphertext-read-error", id)
			continue
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || subtle.ConstantTimeCompare(expected, h.Sum(nil)) != 1 {
			record("error", "ciphertext-checksum-mismatch", id)
		}
	}
	return report, nil
}
