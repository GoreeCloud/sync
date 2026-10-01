package app

import (
	"context"
	"errors"
	"testing"
)

type beginFailureRequestCleanupRuntime struct {
	beginErr      error
	abortRequest  RestoreRequest
	resumeRequest RestoreRequest
	abortCalled   bool
	resumeCalled  bool
}

func (r *beginFailureRequestCleanupRuntime) BeginRestore(context.Context, RestoreRequest) (RestoreLease, error) {
	return RestoreLease{
		LeaseID:   "untrusted-lease",
		AccountID: "foreign-account",
		TargetID:  "foreign-target",
		StagingID: "foreign-staging",
	}, r.beginErr
}

func (*beginFailureRequestCleanupRuntime) CommitAndReconcile(context.Context, RestoreLease) error {
	return nil
}

func (*beginFailureRequestCleanupRuntime) AbortRestore(context.Context, RestoreLease) error {
	return errors.New("lease-scoped abort must not run after begin failure")
}

func (*beginFailureRequestCleanupRuntime) Resume(context.Context, RestoreLease) error {
	return errors.New("lease-scoped resume must not run after begin failure")
}

func (r *beginFailureRequestCleanupRuntime) AbortRestoreRequest(_ context.Context, request RestoreRequest) error {
	r.abortCalled = true
	r.abortRequest = request
	return nil
}

func (r *beginFailureRequestCleanupRuntime) ResumeRestoreRequest(_ context.Context, request RestoreRequest) error {
	r.resumeCalled = true
	r.resumeRequest = request
	return nil
}

func TestRestoreBeginFailureUsesOnlyRequestBoundCleanup(t *testing.T) {
	beginErr := errors.New("runtime partially entered maintenance before begin failed")
	runtime := &beginFailureRequestCleanupRuntime{beginErr: beginErr}
	coordinator := BackupSyncCoordinator{Restore: runtime}
	request := RestoreRequest{
		AccountID:   "acct-1",
		TargetID:    "browser-state",
		OperationID: "restore-partial-begin",
	}
	callbackCalled := false

	err := coordinator.RestoreIntoManagedTarget(context.Background(), request, func(context.Context, RestoreLease) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, beginErr) {
		t.Fatalf("expected begin failure to remain visible, got %v", err)
	}
	if callbackCalled {
		t.Fatal("restore callback must not run after BeginRestore failure")
	}
	if !runtime.abortCalled || !runtime.resumeCalled {
		t.Fatalf("request-bound cleanup not completed: abort=%v resume=%v", runtime.abortCalled, runtime.resumeCalled)
	}
	if runtime.abortRequest != request || runtime.resumeRequest != request {
		t.Fatalf("request-bound cleanup received different authority: abort=%+v resume=%+v", runtime.abortRequest, runtime.resumeRequest)
	}
}
