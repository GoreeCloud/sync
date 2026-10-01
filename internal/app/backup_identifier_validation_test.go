package app

import (
	"strings"
	"testing"
)

func TestCheckpointRequestRejectsAmbiguousIdentifiersAndReason(t *testing.T) {
	base := BackupCheckpointRequest{
		AccountID:   "acct-1",
		ScopeID:     "browser-state",
		OperationID: "migration-1",
		Reason:      "schema migration",
		Requirement: BackupCheckpointRequired,
	}

	cases := []struct {
		name   string
		mutate func(*BackupCheckpointRequest)
	}{
		{"leading account whitespace", func(r *BackupCheckpointRequest) { r.AccountID = " acct-1" }},
		{"trailing scope whitespace", func(r *BackupCheckpointRequest) { r.ScopeID = "browser-state " }},
		{"operation control character", func(r *BackupCheckpointRequest) { r.OperationID = "migration\n1" }},
		{"reason control character", func(r *BackupCheckpointRequest) { r.Reason = "schema\tmigration" }},
		{"oversized operation", func(r *BackupCheckpointRequest) {
			r.OperationID = strings.Repeat("x", maxCoordinationIdentifierLength+1)
		}},
		{"oversized reason", func(r *BackupCheckpointRequest) { r.Reason = strings.Repeat("x", maxCheckpointReasonLength+1) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := base
			tc.mutate(&request)
			if err := validateBackupCheckpointRequest(request); err == nil {
				t.Fatal("ambiguous or unbounded checkpoint request must fail closed")
			}
		})
	}
}

func TestRestoreRequestRejectsAmbiguousIdentifiers(t *testing.T) {
	for name, request := range map[string]RestoreRequest{
		"account whitespace":  {AccountID: "acct-1 ", TargetID: "browser-state", OperationID: "restore-1"},
		"target control":      {AccountID: "acct-1", TargetID: "browser\nstate", OperationID: "restore-1"},
		"operation oversized": {AccountID: "acct-1", TargetID: "browser-state", OperationID: strings.Repeat("x", maxCoordinationIdentifierLength+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRestoreRequest(request); err == nil {
				t.Fatal("ambiguous restore request must fail closed")
			}
		})
	}
}

func TestRestoreLeaseRejectsAmbiguousRuntimeIdentifiers(t *testing.T) {
	request := RestoreRequest{AccountID: "acct-1", TargetID: "browser-state", OperationID: "restore-1"}
	for name, lease := range map[string]RestoreLease{
		"lease whitespace":  {LeaseID: " lease-1", TargetID: request.TargetID, StagingID: "stage-1"},
		"staging control":   {LeaseID: "lease-1", TargetID: request.TargetID, StagingID: "stage\n1"},
		"staging oversized": {LeaseID: "lease-1", TargetID: request.TargetID, StagingID: strings.Repeat("x", maxCoordinationIdentifierLength+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRestoreLease(request, lease); err == nil {
				t.Fatal("ambiguous restore lease must fail closed")
			}
		})
	}
}
