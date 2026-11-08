package syncplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func durableFixtures(t *testing.T, shared bool) (string, string, string) {
	t.Helper()
	left, right := continuousDirs(t)
	state := filepath.Join(filepath.Dir(left), "state.json")
	if shared {
		continuousFile(t, left, "shared.txt", "same")
		continuousFile(t, right, "shared.txt", "same")
	}
	return left, right, state
}

func initDurableForTest(t *testing.T, left, right, state string, excludes []string) DurableState {
	t.Helper()
	s, err := InitDurableState(left, right, state, excludes)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func runDurableOnce(t *testing.T, left, right, state string, excludes []string) []ContinuousAdditionsEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var events []ContinuousAdditionsEvent
	err := RunDurableContinuousAdditions(ctx, left, right, excludes, time.Second, state, func(e ContinuousAdditionsEvent) error {
		events = append(events, e)
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("durable run: %v", err)
	}
	return events
}

func TestInitDurableStateRefusesAmbiguousAndOverwrite(t *testing.T) {
	left, right, state := durableFixtures(t, true)
	continuousFile(t, left, "other.txt", "x")
	if _, err := InitDurableState(left, right, state, nil); err == nil {
		t.Fatal("initialized differing folders")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected state file: %v", err)
	}
	if err := os.Remove(filepath.Join(left, "other.txt")); err != nil {
		t.Fatal(err)
	}
	s := initDurableForTest(t, left, right, state, nil)
	if s.Checksum == "" || s.Generation != 1 || s.Phase != "ready" || len(s.Files) != 1 {
		t.Fatalf("initial state: %+v", s)
	}
	loaded, err := ValidateDurableState(left, right, state, nil)
	if err != nil || loaded.Checksum != s.Checksum {
		t.Fatalf("readback: %v %+v", err, loaded)
	}
	if _, err := InitDurableState(left, right, state, nil); err == nil {
		t.Fatal("overwrote existing history")
	}
	if _, err := InitDurableState(left, right, filepath.Join(left, "history.json"), nil); err == nil {
		t.Fatal("history inside synced tree")
	}
	if _, err := ValidateDurableState(right, left, state, nil); err == nil {
		t.Fatal("accepted reversed roots")
	}
	if _, err := ValidateDurableState(left, right, state, []string{"*.tmp"}); err == nil {
		t.Fatal("accepted differing exclusions")
	}
	info, err := os.Stat(state)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state not private: %v", err)
	}
}

func TestDurableCopiesAndGuardsDeletedFileAcrossRestart(t *testing.T) {
	left, right, state := durableFixtures(t, true)
	initDurableForTest(t, left, right, state, nil)
	continuousFile(t, left, "left.txt", "new-left")
	continuousFile(t, right, "right.txt", "new-right")
	events := runDurableOnce(t, left, right, state, nil)
	if len(events) != 1 || events[0].Type != "snapshot" || events[0].Mode != "durable-foreground-additions" || len(events[0].Result.LeftCreated) != 1 || len(events[0].Result.RightCreated) != 1 {
		t.Fatalf("events: %+v", events)
	}
	for _, pair := range [][2]string{{right, "left.txt"}, {left, "right.txt"}} {
		if _, err := os.Stat(filepath.Join(pair[0], pair[1])); err != nil {
			t.Fatal(err)
		}
	}
	s, err := LoadDurableState(state)
	if err != nil || s.Phase != "ready" || s.Generation != 3 || len(s.Files) != 3 || len(s.Pending) != 0 {
		t.Fatalf("committed state: %v %+v", err, s)
	}
	// Simulate a restart after a user has intentionally deleted a known path.
	if err := os.Remove(filepath.Join(right, "shared.txt")); err != nil {
		t.Fatal(err)
	}
	continuousFile(t, left, "unrelated.txt", "should-not-copy")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var stopped []ContinuousAdditionsEvent
	err = RunDurableContinuousAdditions(ctx, left, right, nil, time.Second, state, func(e ContinuousAdditionsEvent) error { stopped = append(stopped, e); return nil })
	if err == nil || !strings.Contains(err.Error(), "manual deletion/change review") {
		t.Fatalf("missed deletion after restart: %v", err)
	}
	if len(stopped) != 1 || stopped[0].Type != "stopped" {
		t.Fatalf("no fail closed event: %+v", stopped)
	}
	if _, err := os.Stat(filepath.Join(right, "shared.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resurrected deletion: %v", err)
	}
	if _, err := os.Stat(filepath.Join(right, "unrelated.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copied new file despite conflict: %v", err)
	}
	still, err := LoadDurableState(state)
	if err != nil || still.Checksum != s.Checksum {
		t.Fatalf("failed scan rewrote state: %v", err)
	}
}

func TestDurableRejectsRewrittenKnownFilesAndMissingOnBoth(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(map[bool]string{true: "identical rewrite", false: "both deleted"}[both], func(t *testing.T) {
			left, right, state := durableFixtures(t, true)
			initDurableForTest(t, left, right, state, nil)
			if both {
				continuousFile(t, left, "shared.txt", "changed")
				continuousFile(t, right, "shared.txt", "changed")
			} else {
				_ = os.Remove(filepath.Join(left, "shared.txt"))
				_ = os.Remove(filepath.Join(right, "shared.txt"))
			}
			if err := RunDurableContinuousAdditions(context.Background(), left, right, nil, time.Second, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil {
				t.Fatal("accepted known file mutation")
			}
		})
	}
}

func TestDurablePendingRestartRefusesAutomaticRecovery(t *testing.T) {
	left, right, state := durableFixtures(t, true)
	s := initDurableForTest(t, left, right, state, nil)
	pending := s
	pending.Generation++
	pending.Phase = "pending"
	pending.Pending = []PendingCopy{{Path: "new.txt", Direction: "source-to-target", Size: 25, SHA256: sha256Hex([]byte("possibly partially copied"))}}
	_, err := updateDurableState(state, s, pending)
	if err != nil {
		t.Fatal(err)
	}
	continuousFile(t, left, "new.txt", "possibly partially copied")
	if err := RunDurableContinuousAdditions(context.Background(), left, right, nil, time.Second, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("auto resumed pending batch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(right, "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copied despite pending journal: %v", err)
	}
	loaded, err := LoadDurableState(state)
	if err != nil || loaded.Phase != "pending" {
		t.Fatalf("state failed to remain pending: %v", err)
	}
}

func TestDurableStateRejectsTamperSymlinkAndPermissions(t *testing.T) {
	left, right, state := durableFixtures(t, true)
	initDurableForTest(t, left, right, state, nil)
	original, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, append([]byte(nil), append(original, []byte("extra")...)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDurableState(state); err == nil {
		t.Fatal("accepted trailing data")
	}
	if err := os.WriteFile(state, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDurableState(state); err == nil {
		t.Fatal("accepted group-readable state")
	}
	if err := os.Chmod(state, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(left, "shared.txt"), state); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDurableState(state); err == nil {
		t.Fatal("accepted symlink state")
	}
}

func TestDurableRejectsConcurrentWorkers(t *testing.T) {
	left, right, state := durableFixtures(t, false)
	initDurableForTest(t, left, right, state, nil)
	unlock, err := lockDurableState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := RunDurableContinuousAdditions(context.Background(), left, right, nil, time.Second, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("accepted duplicate worker: %v", err)
	}
}

func TestDurableRecordsMatchingNewFilesWithoutCopy(t *testing.T) {
	left, right, state := durableFixtures(t, false)
	initDurableForTest(t, left, right, state, []string{"*.tmp"})
	continuousFile(t, left, "both.txt", "new")
	continuousFile(t, right, "both.txt", "new")
	continuousFile(t, left, "excluded.tmp", "excluded")
	events := runDurableOnce(t, left, right, state, []string{"*.tmp"})
	if len(events) != 1 || events[0].Type != "snapshot" {
		t.Fatalf("events: %+v", events)
	}
	s, err := LoadDurableState(state)
	if err != nil || len(s.Files) != 1 || s.Files[0].Path != "both.txt" || s.Phase != "ready" {
		t.Fatalf("failed to record matching file: %v %+v", err, s)
	}
	if err := os.Remove(filepath.Join(left, "both.txt")); err != nil {
		t.Fatal(err)
	}
	if err := RunDurableContinuousAdditions(context.Background(), left, right, []string{"*.tmp"}, time.Second, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil {
		t.Fatal("resurrected matching file after restart")
	}
}

func TestDurableRejectsInvalidInputs(t *testing.T) {
	left, right, state := durableFixtures(t, false)
	initDurableForTest(t, left, right, state, nil)
	for _, d := range []time.Duration{0, time.Millisecond, 2 * time.Hour} {
		if err := RunDurableContinuousAdditions(context.Background(), left, right, nil, d, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil {
			t.Fatalf("accepted interval %v", d)
		}
	}
	if err := RunDurableContinuousAdditions(context.Background(), left, right, nil, time.Second, state, nil); err == nil {
		t.Fatal("accepted no event sink")
	}
	if err := RunDurableContinuousAdditions(context.Background(), left, left, nil, time.Second, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil {
		t.Fatal("accepted overlapping roots")
	}
}

func sha256Hex(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
