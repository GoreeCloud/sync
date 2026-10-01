package app

import (
	"context"
	"reflect"
	"testing"
)

type cleanupLeaseRecordingRuntime struct {
	lease RestoreLease

	leaseAbortCalled  bool
	leaseResumeCalled bool
	abortRequest      RestoreRequest
	resumeRequest     RestoreRequest
}

func (r *cleanupLeaseRecordingRuntime) BeginRestore(context.Context, RestoreRequest) (RestoreLease, error) {
	return r.lease, nil
}

func (r *cleanupLeaseRecordingRuntime) CommitAndReconcile(context.Context, RestoreLease) error {
	return nil
}

func (r *cleanupLeaseRecordingRuntime) AbortRestore(context.Context, RestoreLease) error {
	r.leaseAbortCalled = true
	return nil
}

func (r *cleanupLeaseRecordingRuntime) Resume(context.Context, RestoreLease) error {
	r.leaseResumeCalled = true
	return nil
}

func (r *cleanupLeaseRecordingRuntime) AbortRestoreRequest(_ context.Context, request RestoreRequest) error {
	r.abortRequest = request
	return nil
}

func (r *cleanupLeaseRecordingRuntime) ResumeRestoreRequest(_ context.Context, request RestoreRequest) error {
	r.resumeRequest = request
	return nil
}

func TestRestoreCleanupDoesNotReuseForeignLeaseAuthority(t *testing.T) {
	request := RestoreRequest{
		AccountID:   "acct-1",
		TargetID:    "browser-state",
		OperationID: "restore-1",
	}
	runtime := &cleanupLeaseRecordingRuntime{lease: RestoreLease{
		LeaseID:     "foreign-lease",
		AccountID:   "acct-2",
		TargetID:    "different-target",
		OperationID: "different-operation",
		StagingID:   "foreign-stage",
	}}
	coordinator := BackupSyncCoordinator{Restore: runtime}
	called := false

	err := coordinator.RestoreIntoManagedTarget(context.Background(), request, func(context.Context, RestoreLease) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("foreign restore lease must fail closed")
	}
	if called {
		t.Fatal("restore callback ran with a foreign restore lease")
	}
	if runtime.leaseAbortCalled || runtime.leaseResumeCalled {
		t.Fatal("invalid lease must never be passed to lease-scoped cleanup")
	}
	if !reflect.DeepEqual(runtime.abortRequest, request) {
		t.Fatalf("abort request = %+v, want %+v", runtime.abortRequest, request)
	}
	if !reflect.DeepEqual(runtime.resumeRequest, request) {
		t.Fatalf("resume request = %+v, want %+v", runtime.resumeRequest, request)
	}
}

type leaseOnlyInvalidCleanupRuntime struct {
	lease             RestoreLease
	leaseAbortCalled  bool
	leaseResumeCalled bool
}

func (r *leaseOnlyInvalidCleanupRuntime) BeginRestore(context.Context, RestoreRequest) (RestoreLease, error) {
	return r.lease, nil
}
func (r *leaseOnlyInvalidCleanupRuntime) CommitAndReconcile(context.Context, RestoreLease) error {
	return nil
}
func (r *leaseOnlyInvalidCleanupRuntime) AbortRestore(context.Context, RestoreLease) error {
	r.leaseAbortCalled = true
	return nil
}
func (r *leaseOnlyInvalidCleanupRuntime) Resume(context.Context, RestoreLease) error {
	r.leaseResumeCalled = true
	return nil
}

func TestInvalidLeaseWithoutRequestCleanupFailsWithoutUsingLeaseCleanup(t *testing.T) {
	runtime := &leaseOnlyInvalidCleanupRuntime{lease: RestoreLease{
		LeaseID:     "foreign-lease",
		AccountID:   "acct-2",
		TargetID:    "different-target",
		OperationID: "different-operation",
		StagingID:   "foreign-stage",
	}}
	coordinator := BackupSyncCoordinator{Restore: runtime}

	err := coordinator.RestoreIntoManagedTarget(context.Background(), RestoreRequest{
		AccountID:   "acct-1",
		TargetID:    "browser-state",
		OperationID: "restore-1",
	}, func(context.Context, RestoreLease) error {
		t.Fatal("restore callback must not run")
		return nil
	})
	if err == nil {
		t.Fatal("foreign restore lease must fail closed")
	}
	if runtime.leaseAbortCalled || runtime.leaseResumeCalled {
		t.Fatal("runtime without request-bound cleanup must not receive invalid lease cleanup")
	}
}
