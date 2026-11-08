package syncplan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWatchChangedContentAndNoWrites(t *testing.T) {
	parent := t.TempDir()
	src, dst := filepath.Join(parent, "left"), filepath.Join(parent, "right")
	for _, dir := range []string{src, dst} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "note.txt"), []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "note.txt"), []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var events []WatchEvent
	err := WatchChanges(ctx, src, dst, "", nil, time.Second, func(event WatchEvent) error {
		events = append(events, event)
		if len(events) == 1 {
			return os.WriteFile(filepath.Join(src, "note.txt"), []byte("after"), 0600)
		}
		cancel()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected initial and changed, got %d", len(events))
	}
	if events[0].Sequence != 1 || events[0].Type != "snapshot" || events[1].Sequence != 2 || events[1].Type != "changed" || !events[1].ReadOnly || events[1].Mode != "two-way" {
		t.Fatalf("bad event sequence: %+v", events)
	}
	var plan Plan
	if err := json.Unmarshal(events[1].Plan, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Different != 1 || !plan.ReadOnly || len(plan.Changes) != 1 || plan.Changes[0].Status != "different" {
		t.Fatalf("unexpected changed plan: %+v", plan)
	}
	target, err := os.ReadFile(filepath.Join(dst, "note.txt"))
	if err != nil || string(target) != "before" {
		t.Fatalf("observer modified target: %q %v", target, err)
	}
}
func TestWatchHistoricalConflict(t *testing.T) {
	parent := t.TempDir()
	src, dst := filepath.Join(parent, "source"), filepath.Join(parent, "target")
	for _, d := range []string{src, dst} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "item.txt"), []byte("shared"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	baseline := filepath.Join(parent, "base.json")
	if _, err := CaptureBaseline(src, dst, baseline, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	events := 0
	err := WatchChanges(ctx, src, dst, baseline, nil, time.Second, func(event WatchEvent) error {
		events++
		if event.Mode != "three-way" || !event.ReadOnly {
			t.Fatalf("bad historical event %+v", event)
		}
		if events == 1 {
			if err := os.WriteFile(filepath.Join(src, "item.txt"), []byte("left edit"), 0600); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dst, "item.txt"), []byte("right edit"), 0600)
		}
		var plan HistoricalPlan
		if err := json.Unmarshal(event.Plan, &plan); err != nil {
			return err
		}
		if plan.Conflicts != 1 || len(plan.Changes) != 1 || plan.Changes[0].Status != "conflict-modify-modify" {
			t.Fatalf("wrong conflict plan: %+v", plan)
		}
		cancel()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("got %d events", events)
	}
	if _, err := os.Stat(baseline); err != nil {
		t.Fatal(err)
	}
}
func TestWatchBaselineMutationFailsClosed(t *testing.T) {
	parent := t.TempDir()
	src, dst := filepath.Join(parent, "a"), filepath.Join(parent, "b")
	for _, d := range []string{src, dst} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	baseline := filepath.Join(parent, "initial.json")
	if _, err := CaptureBaseline(src, dst, baseline, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	events := 0
	err := WatchChanges(ctx, src, dst, baseline, nil, time.Second, func(_ WatchEvent) error {
		events++
		if events == 1 {
			return os.WriteFile(baseline, []byte("invalid checkpoint"), 0600)
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "baseline changed") || events != 1 {
		t.Fatalf("baseline tamper not fail-closed: events=%d err=%v", events, err)
	}
}
func TestWatchRejectsUnsafeOptionsAndStops(t *testing.T) {
	root := t.TempDir()
	for _, in := range []time.Duration{0, 100 * time.Millisecond, 2 * time.Hour} {
		if err := WatchChanges(context.Background(), root, root, "", nil, in, func(WatchEvent) error { return nil }); err == nil {
			t.Fatalf("accepted interval %s", in)
		}
	}
	if err := WatchChanges(context.Background(), root, root, "", nil, time.Second, func(WatchEvent) error { return nil }); err == nil {
		t.Fatal("accepted overlapping roots")
	}
	if err := WatchChanges(context.Background(), root, root, "", nil, time.Second, nil); err == nil {
		t.Fatal("accepted nil callback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second := t.TempDir()
	if err := WatchChanges(ctx, root, second, "", nil, time.Second, func(WatchEvent) error { t.Fatal("canceled watch emitted event"); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestWatchUnchangedSuppressesRepeatedEvents(t *testing.T) {
	parent := t.TempDir()
	left, right := filepath.Join(parent, "left"), filepath.Join(parent, "right")
	for _, d := range []string{left, right} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2250*time.Millisecond)
	defer cancel()
	count := 0
	err := WatchChanges(ctx, left, right, "", nil, time.Second, func(event WatchEvent) error {
		count++
		if event.Sequence != 1 {
			t.Errorf("repeated identical plan: %+v", event)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("identical inventories emitted %d times, want 1", count)
	}
}
func TestWatchFailsOnNewSymlink(t *testing.T) {
	parent := t.TempDir()
	left, right := filepath.Join(parent, "left"), filepath.Join(parent, "right")
	for _, d := range []string{left, right} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	count := 0
	err := WatchChanges(ctx, left, right, "", nil, time.Second, func(WatchEvent) error {
		count++
		if count == 1 {
			return os.Symlink("/etc/passwd", filepath.Join(left, "injected"))
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "symbolic links") || count != 1 {
		t.Fatalf("symlink scan did not fail closed: count=%d error=%v", count, err)
	}
}
