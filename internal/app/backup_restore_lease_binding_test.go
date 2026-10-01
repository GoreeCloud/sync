package app

import (
	"context"
	"reflect"
	"testing"
)

func TestRestoreRejectsLeaseForDifferentAccountOrOperationAndCleansUp(t *testing.T) {
	request := RestoreRequest{
		AccountID:   "acct-1",
		TargetID:    "browser-state",
		OperationID: "restore-1",
	}

	for name, lease := range map[string]RestoreLease{
		"account": {
			LeaseID:     "lease-1",
			AccountID:   "acct-2",
			TargetID:    request.TargetID,
			OperationID: request.OperationID,
			StagingID:   "stage-1",
		},
		"operation": {
			LeaseID:     "lease-1",
			AccountID:   request.AccountID,
			TargetID:    request.TargetID,
			OperationID: "restore-2",
			StagingID:   "stage-1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtime := &fakeRestoreRuntime{lease: lease}
			coordinator := BackupSyncCoordinator{Restore: runtime}
			called := false

			err := coordinator.RestoreIntoManagedTarget(context.Background(), request, func(context.Context, RestoreLease) error {
				called = true
				return nil
			})
			if err == nil {
				t.Fatal("lease bound to a different request must fail closed")
			}
			if called {
				t.Fatal("restore callback ran with a lease bound to a different request")
			}
			wantCalls := []string{"begin", "abort", "resume"}
			if !reflect.DeepEqual(runtime.calls, wantCalls) {
				t.Fatalf("restore call order = %v, want %v", runtime.calls, wantCalls)
			}
		})
	}
}
