package app

import "context"

// Keep the shared fake runtime aligned with the request-bound cleanup contract
// used only when BeginRestore returned an invalid lease. Existing valid-lease
// tests continue to exercise the lease-scoped AbortRestore/Resume methods.
func (f *fakeRestoreRuntime) AbortRestoreRequest(ctx context.Context, _ RestoreRequest) error {
	f.calls = append(f.calls, "abort")
	f.abortContextErr = ctx.Err()
	_, f.abortHasDeadline = ctx.Deadline()
	return f.abortErr
}

func (f *fakeRestoreRuntime) ResumeRestoreRequest(ctx context.Context, _ RestoreRequest) error {
	f.calls = append(f.calls, "resume")
	f.resumeContextErr = ctx.Err()
	_, f.resumeHasDeadline = ctx.Deadline()
	return f.resumeErr
}
