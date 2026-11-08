package syncplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func continuousDirs(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	left, right := filepath.Join(root, "left"), filepath.Join(root, "right")
	for _, d := range []string{left, right} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return left, right
}
func continuousFile(t *testing.T, dir, rel, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestContinuousAdditionsCopiesBothAndStopsOnCancel(t *testing.T) {
	left, right := continuousDirs(t)
	state := filepath.Join(filepath.Dir(left), "state.json")
	initDurableForTest(t, left, right, state, nil)
	continuousFile(t, left, "left.txt", "L")
	continuousFile(t, right, "right.txt", "R")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var events []ContinuousAdditionsEvent
	err := RunDurableContinuousAdditions(ctx, left, right, nil, time.Second, state, func(e ContinuousAdditionsEvent) error {
		events = append(events, e)
		if len(events) == 1 {
			if e.Type != "snapshot" || !e.Result.Applied || len(e.Result.LeftCreated) != 1 || len(e.Result.RightCreated) != 1 || e.Result.BytesWritten != 2 {
				t.Fatalf("first result: %+v", e)
			}
			continuousFile(t, left, "next.txt", "next")
		} else {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Type != "applied" || events[1].Sequence != 2 || !events[1].AdditionsOnly {
		t.Fatalf("events: %+v", events)
	}
	for _, path := range []string{filepath.Join(left, "right.txt"), filepath.Join(right, "left.txt"), filepath.Join(right, "next.txt")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}
func TestContinuousAdditionsStopsOnConflictWithoutCopy(t *testing.T) {
	left, right := continuousDirs(t)
	continuousFile(t, left, "common.txt", "same")
	continuousFile(t, right, "common.txt", "same")
	state := filepath.Join(filepath.Dir(left), "state.json")
	initDurableForTest(t, left, right, state, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var events []ContinuousAdditionsEvent
	err := RunDurableContinuousAdditions(ctx, left, right, nil, time.Second, state, func(e ContinuousAdditionsEvent) error {
		events = append(events, e)
		if len(events) == 1 {
			continuousFile(t, left, "common.txt", "LEFT")
			continuousFile(t, right, "common.txt", "RIGHT")
			continuousFile(t, left, "must-not-copy.txt", "blocked")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "manual deletion/change review") {
		t.Fatalf("expected fail closed conflict: %v", err)
	}
	if len(events) != 2 || events[1].Type != "stopped" || events[1].Error == "" || events[1].Result.Applied {
		t.Fatalf("events: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(right, "must-not-copy.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("conflict copied file: %v", err)
	}
}
func TestContinuousAdditionsExclusionsAndQuietScan(t *testing.T) {
	left, right := continuousDirs(t)
	continuousFile(t, left, "ignore.tmp", "not copied")
	state := filepath.Join(filepath.Dir(left), "state.json")
	initDurableForTest(t, left, right, state, []string{"*.tmp"})
	ctx, cancel := context.WithTimeout(context.Background(), 2250*time.Millisecond)
	defer cancel()
	events := 0
	err := RunDurableContinuousAdditions(ctx, left, right, []string{"*.tmp"}, time.Second, state, func(e ContinuousAdditionsEvent) error {
		events++
		if e.Type != "snapshot" || len(e.Result.LeftCreated)+len(e.Result.RightCreated) != 0 {
			t.Errorf("unexpected event %+v", e)
		}
		return nil
	})
	if err != nil || events != 1 {
		t.Fatalf("events=%d err=%v", events, err)
	}
	if _, err := os.Stat(filepath.Join(right, "ignore.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("excluded file copied: %v", err)
	}
}
func TestContinuousAdditionsRejectsUnsafeAndCanceled(t *testing.T) {
	a, b := continuousDirs(t)
	state := filepath.Join(filepath.Dir(a), "state.json")
	initDurableForTest(t, a, b, state, nil)
	for _, interval := range []time.Duration{0, time.Millisecond, 2 * time.Hour} {
		if err := RunDurableContinuousAdditions(context.Background(), a, b, nil, interval, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil {
			t.Fatalf("accepted invalid interval %s", interval)
		}
	}
	if err := RunDurableContinuousAdditions(context.Background(), a, a, nil, time.Second, state, func(ContinuousAdditionsEvent) error { return nil }); err == nil {
		t.Fatal("accepted same root")
	}
	if err := RunDurableContinuousAdditions(context.Background(), a, b, nil, time.Second, state, nil); err == nil {
		t.Fatal("accepted nil emitter")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunDurableContinuousAdditions(ctx, a, b, nil, time.Second, state, func(ContinuousAdditionsEvent) error { t.Fatal("emitted after cancellation"); return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestContinuousAdditionsStopsOnSymlinkAfterFirstCycle(t *testing.T) {
	left, right := continuousDirs(t)
	state := filepath.Join(filepath.Dir(left), "state.json")
	initDurableForTest(t, left, right, state, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	events := 0
	err := RunDurableContinuousAdditions(ctx, left, right, nil, time.Second, state, func(e ContinuousAdditionsEvent) error {
		events++
		if events == 1 {
			return os.Symlink(filepath.Join(left, "missing"), filepath.Join(left, "link.txt"))
		}
		return nil
	})
	if err == nil || events != 2 {
		t.Fatalf("must stop on symlink, events=%d err=%v", events, err)
	}
}

func TestContinuousAdditionsRejectsDeletionResurrectionDuringSession(t *testing.T) {
	left, right := continuousDirs(t)
	continuousFile(t, left, "shared.txt", "identical")
	continuousFile(t, right, "shared.txt", "identical")
	state := filepath.Join(filepath.Dir(left), "state.json")
	initDurableForTest(t, left, right, state, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	events := []ContinuousAdditionsEvent{}
	err := RunDurableContinuousAdditions(ctx, left, right, nil, time.Second, state, func(e ContinuousAdditionsEvent) error {
		events = append(events, e)
		if len(events) == 1 {
			if err := os.Remove(filepath.Join(right, "shared.txt")); err != nil {
				return err
			}
			continuousFile(t, left, "other.txt", "should not be copied")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "manual deletion/change review") {
		t.Fatalf("should fail closed on deletion: %v", err)
	}
	if len(events) != 2 || events[1].Type != "stopped" {
		t.Fatalf("wrong events: %+v", events)
	}
	if _, err := os.Stat(filepath.Join(right, "shared.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resurrected deleted file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(right, "other.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("copied unrelated new file during conflict: %v", err)
	}
}
