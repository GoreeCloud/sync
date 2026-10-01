package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

var ErrBackupUnavailable = errors.New("backup service unavailable")

const (
	restoreCleanupTimeout           = 5 * time.Second
	maxCoordinationIdentifierLength = 256
	maxCheckpointReasonLength       = 512
	maxProtectionDetailLength       = 1000
)

// BackupProtectionState is descriptive evidence supplied by the Backup
// authority. Sync may present or use this state for orchestration decisions, but
// it must not reinterpret the state as Sync authorization or delete Backup data.
type BackupProtectionState struct {
	Available        bool
	Protected        bool
	LatestCheckpoint string
	ObservedAt       time.Time
	Detail           string
}

// BackupProtectionStateProvider exposes Backup-owned protection state to Sync.
// The interface is intentionally read-only and contains no deletion operation.
type BackupProtectionStateProvider interface {
	ProtectionState(ctx context.Context, accountID, scopeID string) (BackupProtectionState, error)
}

type BackupCheckpointRequirement int

const (
	BackupCheckpointBestEffort BackupCheckpointRequirement = iota
	BackupCheckpointRequired
)

// BackupCheckpointRequest asks Backup to create a pre-change/pre-migration
// checkpoint for a Sync-owned scope. Backup remains authoritative for whether
// and how that checkpoint is created and retained.
type BackupCheckpointRequest struct {
	AccountID   string
	ScopeID     string
	OperationID string
	Reason      string
	Requirement BackupCheckpointRequirement
}

// BackupCheckpointReceipt binds Backup's result to the exact authorized request
// so a receipt for another account, scope, or operation cannot be replayed as
// evidence for this checkpoint request.
type BackupCheckpointReceipt struct {
	CheckpointID string
	AccountID    string
	ScopeID      string
	OperationID  string
	CreatedAt    time.Time
}

// BackupCheckpointAuthorizer is a separate authorization boundary. A caller
// cannot create a checkpoint merely by being able to reach Backup.
type BackupCheckpointAuthorizer interface {
	AuthorizeCheckpoint(ctx context.Context, request BackupCheckpointRequest) error
}

// BackupCheckpointAuthority is deliberately limited to checkpoint creation.
// Backup deletion authority does not belong to Sync and is not represented here.
type BackupCheckpointAuthority interface {
	CreateCheckpoint(ctx context.Context, request BackupCheckpointRequest) (BackupCheckpointReceipt, error)
}

type BackupCheckpointOutcome struct {
	BackupAvailable bool
	Created         bool
	Receipt         BackupCheckpointReceipt
	Detail          string
}

// RestoreRequest identifies a Sync-managed restore target by logical authority
// identifiers rather than caller-supplied filesystem paths.
type RestoreRequest struct {
	AccountID   string
	TargetID    string
	OperationID string
}

// RestoreLease is issued by the Sync runtime after it has authorized the exact
// account, target, and operation, paused mutations for that target, and created
// an isolated staging area. The staging identifier is opaque; callers do not get
// destination-path authority.
type RestoreLease struct {
	LeaseID     string
	AccountID   string
	TargetID    string
	OperationID string
	StagingID   string
}

// SyncRestoreRuntime owns the Sync-side restore lifecycle for Sync-managed
// targets. It is responsible for target authorization, pause/maintenance state,
// isolated staging, reconciliation/publication, abort cleanup, and resume.
type SyncRestoreRuntime interface {
	BeginRestore(ctx context.Context, request RestoreRequest) (RestoreLease, error)
	CommitAndReconcile(ctx context.Context, lease RestoreLease) error
	AbortRestore(ctx context.Context, lease RestoreLease) error
	Resume(ctx context.Context, lease RestoreLease) error
}

// SyncRestoreRequestCleanupRuntime is the fail-closed cleanup boundary used when
// BeginRestore fails or returns an invalid lease. The coordinator must not feed a
// foreign or malformed lease back into lease-scoped cleanup operations. A runtime
// that can safely unwind a partially begun restore without trusting the returned
// lease may implement these exact request-bound methods.
type SyncRestoreRequestCleanupRuntime interface {
	AbortRestoreRequest(ctx context.Context, request RestoreRequest) error
	ResumeRestoreRequest(ctx context.Context, request RestoreRequest) error
}

// BackupSyncCoordinator composes Backup-owned protection/checkpoint authority
// with Sync-owned restore orchestration without transferring authority between
// the two services.
type BackupSyncCoordinator struct {
	Protection BackupProtectionStateProvider
	Checkpoint BackupCheckpointAuthority
	Authorizer BackupCheckpointAuthorizer
	Restore    SyncRestoreRuntime
}

// ProtectionState returns Backup's independent protection state. Backup
// unavailability is represented explicitly rather than being mistaken for an
// unprotected or protected state. Available evidence must carry a real,
// non-future observation time; provider-supplied detail and checkpoint identity
// are also bounded/canonical before Sync exposes them.
func (c BackupSyncCoordinator) ProtectionState(ctx context.Context, accountID, scopeID string) (BackupProtectionState, error) {
	if err := validateCoordinationIdentifier(accountID, "account ID"); err != nil {
		return BackupProtectionState{}, err
	}
	if err := validateCoordinationIdentifier(scopeID, "scope ID"); err != nil {
		return BackupProtectionState{}, err
	}
	if c.Protection == nil {
		return BackupProtectionState{Available: false, Detail: "backup protection state provider is not configured"}, nil
	}

	state, err := c.Protection.ProtectionState(ctx, accountID, scopeID)
	if errors.Is(err, ErrBackupUnavailable) {
		return BackupProtectionState{Available: false, Detail: ErrBackupUnavailable.Error()}, nil
	}
	if err != nil {
		return BackupProtectionState{}, err
	}
	if err := validateOptionalProviderText(state.Detail, "backup protection detail", maxProtectionDetailLength); err != nil {
		return BackupProtectionState{}, fmt.Errorf("backup returned invalid protection state: %w", err)
	}
	if !state.Available {
		state.Protected = false
		state.LatestCheckpoint = ""
		state.ObservedAt = time.Time{}
		return state, nil
	}
	if state.LatestCheckpoint != "" {
		if err := validateCoordinationIdentifier(state.LatestCheckpoint, "latest checkpoint ID"); err != nil {
			return BackupProtectionState{}, fmt.Errorf("backup returned invalid protection state: %w", err)
		}
	}
	if state.ObservedAt.IsZero() {
		return BackupProtectionState{}, fmt.Errorf("available backup protection state is missing observed time")
	}
	if state.ObservedAt.After(time.Now().UTC()) {
		return BackupProtectionState{}, fmt.Errorf("backup protection state cannot be observed in the future")
	}
	return state, nil
}

// CheckpointBeforeChange requests an authorized Backup checkpoint before a
// bounded change or migration. Required checkpoints fail closed when Backup is
// unavailable; best-effort checkpoints degrade explicitly and allow the caller
// to decide whether the underlying non-destructive operation may continue.
func (c BackupSyncCoordinator) CheckpointBeforeChange(ctx context.Context, request BackupCheckpointRequest) (BackupCheckpointOutcome, error) {
	if err := validateBackupCheckpointRequest(request); err != nil {
		return BackupCheckpointOutcome{}, err
	}
	if c.Authorizer == nil {
		return BackupCheckpointOutcome{}, fmt.Errorf("backup checkpoint authorizer is not configured")
	}
	if err := c.Authorizer.AuthorizeCheckpoint(ctx, request); err != nil {
		return BackupCheckpointOutcome{}, fmt.Errorf("authorize backup checkpoint: %w", err)
	}
	if c.Checkpoint == nil {
		if request.Requirement == BackupCheckpointRequired {
			return BackupCheckpointOutcome{}, fmt.Errorf("required backup checkpoint: %w", ErrBackupUnavailable)
		}
		return BackupCheckpointOutcome{
			BackupAvailable: false,
			Detail:          "backup checkpoint authority is not configured",
		}, nil
	}

	receipt, err := c.Checkpoint.CreateCheckpoint(ctx, request)
	if errors.Is(err, ErrBackupUnavailable) {
		if request.Requirement == BackupCheckpointRequired {
			return BackupCheckpointOutcome{}, fmt.Errorf("required backup checkpoint: %w", err)
		}
		return BackupCheckpointOutcome{BackupAvailable: false, Detail: ErrBackupUnavailable.Error()}, nil
	}
	if err != nil {
		return BackupCheckpointOutcome{}, err
	}
	if err := validateBackupCheckpointReceipt(request, receipt); err != nil {
		return BackupCheckpointOutcome{}, err
	}
	return BackupCheckpointOutcome{
		BackupAvailable: true,
		Created:         true,
		Receipt:         receipt,
	}, nil
}

// RestoreIntoManagedTarget coordinates a restore into an already-authorized
// Sync-managed logical target. Restore bytes are written only through an opaque
// staging identifier issued by the Sync runtime. Publication happens only after
// successful staging and Sync-owned reconciliation. Once a valid lease has begun,
// abort and resume cleanup each receive their own bounded cleanup context that
// survives cancellation of the caller's request context. If BeginRestore fails
// or returns an invalid lease, lease-scoped cleanup is never called with any
// untrusted lease; only an optional request-bound cleanup interface may unwind
// the exact validated request.
func (c BackupSyncCoordinator) RestoreIntoManagedTarget(ctx context.Context, request RestoreRequest, restore func(context.Context, RestoreLease) error) (err error) {
	if err := validateRestoreRequest(request); err != nil {
		return err
	}
	if c.Restore == nil {
		return fmt.Errorf("sync restore runtime is not configured")
	}
	if restore == nil {
		return fmt.Errorf("restore callback must not be nil")
	}

	lease, err := c.Restore.BeginRestore(ctx, request)
	if err != nil {
		return errors.Join(err, c.cleanupRestoreRequest(ctx, request))
	}
	if err := validateRestoreLease(request, lease); err != nil {
		return errors.Join(err, c.cleanupRestoreRequest(ctx, request))
	}

	defer func() {
		resumeErr := runRestoreCleanup(ctx, func(cleanupCtx context.Context) error {
			return c.Restore.Resume(cleanupCtx, lease)
		})
		err = errors.Join(err, resumeErr)
	}()

	if err := restore(ctx, lease); err != nil {
		abortErr := runRestoreCleanup(ctx, func(cleanupCtx context.Context) error {
			return c.Restore.AbortRestore(cleanupCtx, lease)
		})
		return errors.Join(err, abortErr)
	}
	if err := c.Restore.CommitAndReconcile(ctx, lease); err != nil {
		abortErr := runRestoreCleanup(ctx, func(cleanupCtx context.Context) error {
			return c.Restore.AbortRestore(cleanupCtx, lease)
		})
		return errors.Join(err, abortErr)
	}
	return nil
}

func (c BackupSyncCoordinator) cleanupRestoreRequest(ctx context.Context, request RestoreRequest) error {
	requestCleanup, ok := c.Restore.(SyncRestoreRequestCleanupRuntime)
	if !ok {
		return nil
	}
	abortErr := runRestoreCleanup(ctx, func(cleanupCtx context.Context) error {
		return requestCleanup.AbortRestoreRequest(cleanupCtx, request)
	})
	resumeErr := runRestoreCleanup(ctx, func(cleanupCtx context.Context) error {
		return requestCleanup.ResumeRestoreRequest(cleanupCtx, request)
	})
	return errors.Join(abortErr, resumeErr)
}

func runRestoreCleanup(parent context.Context, operation func(context.Context) error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), restoreCleanupTimeout)
	defer cancel()
	return operation(cleanupCtx)
}

func validateCoordinationIdentifier(value, field string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be a non-empty canonical identifier", field)
	}
	if len(value) > maxCoordinationIdentifierLength {
		return fmt.Errorf("%s exceeds %d characters", field, maxCoordinationIdentifierLength)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

func validateOptionalProviderText(value, field string, maximum int) error {
	if value == "" {
		return nil
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must be canonical", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d characters", field, maximum)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

func validateCheckpointReason(value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("checkpoint reason must be non-empty and canonical")
	}
	if len(value) > maxCheckpointReasonLength {
		return fmt.Errorf("checkpoint reason exceeds %d characters", maxCheckpointReasonLength)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("checkpoint reason contains control characters")
	}
	return nil
}

func validateBackupCheckpointRequest(request BackupCheckpointRequest) error {
	if err := validateCoordinationIdentifier(request.AccountID, "account ID"); err != nil {
		return err
	}
	if err := validateCoordinationIdentifier(request.ScopeID, "scope ID"); err != nil {
		return err
	}
	if err := validateCoordinationIdentifier(request.OperationID, "operation ID"); err != nil {
		return err
	}
	if err := validateCheckpointReason(request.Reason); err != nil {
		return err
	}
	if request.Requirement != BackupCheckpointBestEffort && request.Requirement != BackupCheckpointRequired {
		return fmt.Errorf("invalid backup checkpoint requirement")
	}
	return nil
}

func validateBackupCheckpointReceipt(request BackupCheckpointRequest, receipt BackupCheckpointReceipt) error {
	if err := validateCoordinationIdentifier(receipt.CheckpointID, "checkpoint ID"); err != nil {
		return fmt.Errorf("backup returned an invalid checkpoint receipt: %w", err)
	}
	if receipt.CreatedAt.IsZero() {
		return fmt.Errorf("backup returned an invalid checkpoint receipt")
	}
	if receipt.CreatedAt.After(time.Now().UTC()) {
		return fmt.Errorf("backup checkpoint receipt cannot be created in the future")
	}
	if receipt.AccountID != request.AccountID {
		return fmt.Errorf("backup checkpoint receipt account does not match the authorized request")
	}
	if receipt.ScopeID != request.ScopeID {
		return fmt.Errorf("backup checkpoint receipt scope does not match the authorized request")
	}
	if receipt.OperationID != request.OperationID {
		return fmt.Errorf("backup checkpoint receipt operation does not match the authorized request")
	}
	return nil
}

func validateRestoreRequest(request RestoreRequest) error {
	if err := validateCoordinationIdentifier(request.AccountID, "account ID"); err != nil {
		return err
	}
	if err := validateCoordinationIdentifier(request.TargetID, "restore target ID"); err != nil {
		return err
	}
	if err := validateCoordinationIdentifier(request.OperationID, "operation ID"); err != nil {
		return err
	}
	return nil
}

func validateRestoreLease(request RestoreRequest, lease RestoreLease) error {
	if err := validateCoordinationIdentifier(lease.LeaseID, "restore lease ID"); err != nil {
		return fmt.Errorf("sync restore runtime returned an invalid lease ID: %w", err)
	}
	if lease.AccountID != request.AccountID {
		return fmt.Errorf("sync restore runtime returned a lease for the wrong account")
	}
	if lease.TargetID != request.TargetID {
		return fmt.Errorf("sync restore runtime returned a lease for the wrong target")
	}
	if lease.OperationID != request.OperationID {
		return fmt.Errorf("sync restore runtime returned a lease for the wrong operation")
	}
	if err := validateCoordinationIdentifier(lease.StagingID, "restore staging ID"); err != nil {
		return fmt.Errorf("sync restore runtime returned an invalid staging ID: %w", err)
	}
	return nil
}
