package lansend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReceiverStageResidueAuditFailClosed(t *testing.T) {
	root := privateDir(t)
	report, err := AuditReceiverDirectory(root)
	if err != nil || report.Status != "clear" || report.StageResidueCount != 0 {
		t.Fatalf("initial private audit: %+v, %v", report, err)
	}
	valid := filepath.Join(root, "photo.jpg")
	if err := os.WriteFile(valid, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, ".gcsend-stage-crash")
	if err := os.WriteFile(artifact, []byte("SENSITIVE-UNPUBLISHED-CONTENT"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = AuditReceiverDirectory(root)
	if err != nil || report.Status != "manual-review-required" || report.StageResidueCount != 1 || len(report.StageResidues) != 1 || report.StageResidues[0] != filepath.Base(artifact) {
		t.Fatalf("artifact audit: %+v, %v", report, err)
	}
	if _, _, err := NewReceiver(root); err == nil || !strings.Contains(err.Error(), "staging") {
		t.Fatalf("receiver accepted crash residue: %v", err)
	}
	if err := SaveNew(root, "new.txt", []byte("new")); err == nil || !strings.Contains(err.Error(), "staging") {
		t.Fatalf("save accepted crash residue: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected new file: %v", err)
	}
	preserved, err := os.ReadFile(artifact)
	if err != nil || string(preserved) != "SENSITIVE-UNPUBLISHED-CONTENT" {
		t.Fatalf("artifact was damaged: %v", err)
	}
	preserved, err = os.ReadFile(valid)
	if err != nil || string(preserved) != "preserved" {
		t.Fatalf("unrelated file changed: %v", err)
	}
	// A deliberate manual action outside the application is required.
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := SaveNew(root, "new.txt", []byte("new")); err != nil {
		t.Fatal(err)
	}
	report, err = AuditReceiverDirectory(root)
	if err != nil || report.StageResidueCount != 0 {
		t.Fatalf("post-reconciliation audit: %+v, %v", report, err)
	}
}

func TestReceiverStageResidueAuditNamesBounded(t *testing.T) {
	root := privateDir(t)
	for i := 0; i < receiverAuditNameLimit+8; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf(".gcsend-stage-%03d", i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := AuditReceiverDirectory(root)
	if err != nil || report.StageResidueCount != receiverAuditNameLimit+8 || len(report.StageResidues) != receiverAuditNameLimit || !report.NamesTruncated {
		t.Fatalf("bounded audit: %+v, %v", report, err)
	}
}

func TestReceiverStageResidueAuditUntrustedEntries(t *testing.T) {
	root := privateDir(t)
	if err := os.WriteFile(filepath.Join(root, "ordinary.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ordinary.txt", filepath.Join(root, ".gcsend-stage-symlink")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report, err := AuditReceiverDirectory(root)
	if err != nil || report.StageResidueCount != 1 {
		t.Fatalf("symlink audit: %+v, %v", report, err)
	}
	if _, _, err := NewReceiver(root); err == nil {
		t.Fatal("symlink residue accepted")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := AuditReceiverDirectory(root); err == nil {
		t.Fatal("world-readable destination accepted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := AuditReceiverDirectory(link); err == nil {
		t.Fatal("symlink root accepted")
	}
}
