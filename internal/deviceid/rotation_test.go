package deviceid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationProofAndManualTrust(t *testing.T) {
	peerRoot, oldRoot, newRoot := tDir(t), tDir(t), tDir(t)
	if _, err := Initialize(peerRoot); err != nil {
		t.Fatal(err)
	}
	oldPub, err := Initialize(oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	newPub, err := Initialize(newRoot)
	if err != nil {
		t.Fatal(err)
	}
	oldID, _ := Load(oldRoot)
	newID, _ := Load(newRoot)
	if _, err := Trust(peerRoot, oldPub.PublicKey, oldPub.Fingerprint); err != nil {
		t.Fatal(err)
	}
	proof, err := MakeRotationProof(oldID, newID)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Version != 1 || proof.New != newPub || proof.Old != oldPub {
		t.Fatal("unexpected rotation payload")
	}
	previous, _ := ParsePublic(oldPub.PublicKey)
	checked, err := VerifyRotationProof(proof, previous)
	if err != nil || checked != newPub {
		t.Fatalf("rotation verification: %v %v", checked, err)
	}
	if _, err := VerifyPinnedRotation(peerRoot, oldPub.Fingerprint, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(peerRoot, newPub.Fingerprint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verification unexpectedly enrolled peer: %v", err)
	}
	if _, err := TrustRotation(peerRoot, oldPub.Fingerprint, proof, oldPub.Fingerprint); err == nil {
		t.Fatal("accepted unverified new identity")
	}
	if _, err := TrustRotation(peerRoot, oldPub.Fingerprint, proof, newPub.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := Lookup(peerRoot, oldPub.Fingerprint); err != nil {
		t.Fatal("silently revoked old identity", err)
	}
	if _, err := Lookup(peerRoot, newPub.Fingerprint); err != nil {
		t.Fatal("new identity not enrolled", err)
	}
	if _, err := TrustRotation(peerRoot, oldPub.Fingerprint, proof, newPub.Fingerprint); !errors.Is(err, os.ErrExist) {
		t.Fatalf("rotation overwrote existing pin: %v", err)
	}
	if err := Untrust(peerRoot, oldPub.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPinnedRotation(peerRoot, oldPub.Fingerprint, proof); err == nil {
		t.Fatal("accepted revoked predecessor")
	}
	if _, err := Lookup(peerRoot, newPub.Fingerprint); err != nil {
		t.Fatal("wrong pin revoked", err)
	}
}

func TestRotationProofRejectsTamperAndImpersonation(t *testing.T) {
	root, next, rogue := tDir(t), tDir(t), tDir(t)
	Initialize(root)
	Initialize(next)
	Initialize(rogue)
	old, _ := Load(root)
	replacement, _ := Load(next)
	attacker, _ := Load(rogue)
	proof, err := MakeRotationProof(old, replacement)
	if err != nil {
		t.Fatal(err)
	}
	trustedOld, _ := ParsePublic(old.Public().PublicKey)
	clone := func() RotationProof { return proof }
	tests := []struct {
		name   string
		mutate func(*RotationProof)
	}{
		{"wrong-version", func(p *RotationProof) { p.Version = 2 }},
		{"old-fingerprint", func(p *RotationProof) { p.Old.Fingerprint = attacker.Public().Fingerprint }},
		{"new-fingerprint", func(p *RotationProof) { p.New.Fingerprint = attacker.Public().Fingerprint }},
		{"new-key", func(p *RotationProof) {
			p.New.PublicKey = attacker.Public().PublicKey
			p.New.Fingerprint = attacker.Public().Fingerprint
		}},
		{"changed-old-signature", func(p *RotationProof) { p.OldSignature = p.NewSignature }},
		{"changed-new-signature", func(p *RotationProof) { p.NewSignature = p.OldSignature }},
		{"empty-new-signature", func(p *RotationProof) { p.NewSignature = "" }},
		{"noncanonical-algorithm", func(p *RotationProof) { p.Old.Algorithm = "ed25519" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := clone()
			tc.mutate(&p)
			if _, err := VerifyRotationProof(p, trustedOld); err == nil {
				t.Fatal("accepted tampered proof")
			}
		})
	}
	roguePub, _ := ParsePublic(attacker.Public().PublicKey)
	if _, err := VerifyRotationProof(proof, roguePub); err == nil {
		t.Fatal("proof by untrusted predecessor accepted")
	}
	if _, err := MakeRotationProof(old, old); err == nil {
		t.Fatal("self rotation accepted")
	}
	if _, err := MakeRotationProof(nil, replacement); err == nil {
		t.Fatal("missing old accepted")
	}
	if _, err := MakeRotationProof(old, nil); err == nil {
		t.Fatal("missing new accepted")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyRotationProof(proof, otherPub); err == nil {
		t.Fatal("unknown old key accepted")
	}
}

func TestReadRotationProofRejectsInvalidInput(t *testing.T) {
	root, next := tDir(t), tDir(t)
	Initialize(root)
	Initialize(next)
	a, _ := Load(root)
	b, _ := Load(next)
	p, _ := MakeRotationProof(a, b)
	path := filepath.Join(t.TempDir(), "proof.json")
	data, _ := json.Marshal(p)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRotationProof(path)
	if err != nil || got != p {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if err := os.WriteFile(path, append(data, []byte(" garbage")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRotationProof(path); err == nil {
		t.Fatal("trailing data accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("X", maxRotationProofBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRotationProof(path); err == nil {
		t.Fatal("oversized proof accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRotationProof(path); err == nil {
		t.Fatal("symlink accepted")
	}
}
