package syncplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// WatchEvent is a complete, read-only inventory snapshot. Changed events
// contain the full current plan, not a potentially lossy list of transitions.
// Consumers must never interpret a reported deletion as authorization to act.
type WatchEvent struct {
	Type       string          `json:"type"` // snapshot or changed
	Sequence   uint64          `json:"sequence"`
	ObservedAt time.Time       `json:"observedAt"`
	ReadOnly   bool            `json:"readOnly"`
	Mode       string          `json:"mode"` // two-way or three-way
	Plan       json.RawMessage `json:"plan"`
}

// WatchChanges hashes both local folder trees at a bounded polling interval.
// It emits one initial snapshot and subsequent snapshots ONLY when the
// comparison materially differs. Nothing is copied, deleted or modified.
// The baseline (when provided) is pinned to its original validated contents;
// any in-place change causes a fail-closed error instead of reinterpreting
// historical deletes or conflicts against a different checkpoint.
//
// WatchChanges runs in the foreground until context cancellation or error.
// This is not a filesystem watcher, crash-proof change log, or sync engine:
// intermediate mutations between polling intervals are not guaranteed visible.
func WatchChanges(ctx context.Context, source, target, baseline string, excludes []string, interval time.Duration, emit func(WatchEvent) error) error {
	if ctx == nil || emit == nil {
		return errors.New("watch requires a context and an event writer")
	}
	if interval < time.Second || interval > time.Hour {
		return errors.New("watch interval must be between 1s and 1h")
	}
	if err := isolatedRoots(source, target); err != nil {
		return err
	}
	if _, err := normalizedExcludes(excludes); err != nil {
		return err
	}
	var frozen Baseline
	if baseline != "" {
		var err error
		frozen, err = LoadBaseline(baseline)
		if err != nil {
			return fmt.Errorf("watch baseline: %w", err)
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var previous []byte
	var sequence uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil // requested foreground shutdown is clean
		}
		var plan []byte
		mode := "two-way"
		if baseline != "" {
			current, err := LoadBaseline(baseline)
			if err != nil || !reflect.DeepEqual(frozen, current) {
				return errors.New("watch baseline changed or became unreadable; stopping to avoid misleading results")
			}
			result, err := CompareHistorical(source, target, baseline, excludes)
			if err != nil {
				return fmt.Errorf("watch historical scan: %w", err)
			}
			current, err = LoadBaseline(baseline)
			if err != nil || !reflect.DeepEqual(frozen, current) {
				return errors.New("watch baseline changed during scan; refusing results")
			}
			plan, err = json.Marshal(result)
			if err != nil {
				return err
			}
			mode = "three-way"
		} else {
			result, err := CompareFiltered(source, target, excludes)
			if err != nil {
				return fmt.Errorf("watch folder scan: %w", err)
			}
			plan, err = json.Marshal(result)
			if err != nil {
				return err
			}
		}
		if !bytes.Equal(plan, previous) {
			sequence++
			kind := "changed"
			if sequence == 1 {
				kind = "snapshot"
			}
			// Pass a fresh immutable copy to the caller. Hash contents are
			// never reduced to mtimes or sizes alone.
			event := WatchEvent{Type: kind, Sequence: sequence, ObservedAt: time.Now().UTC(), ReadOnly: true, Mode: mode, Plan: append(json.RawMessage(nil), plan...)}
			if err := emit(event); err != nil {
				return fmt.Errorf("write watch event: %w", err)
			}
			previous = plan
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
