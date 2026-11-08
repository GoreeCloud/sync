package syncplan

import (
	"fmt"
)

const MaxDurableAuditIssues = 128

type DurableAuditIssue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// DurableAudit reports CURRENT inventory discrepancies against the pinned
// history, without changing that history or authorizing recovery or deletes.
// SafeToRun is a best-effort snapshot, not an atomic filesystem guarantee.
type DurableAudit struct {
	Mode            string              `json:"mode"`
	ReadOnly        bool                `json:"readOnly"`
	Version         int                 `json:"version"`
	Generation      uint64              `json:"generation"`
	Phase           string              `json:"phase"`
	KnownFiles      int                 `json:"knownFiles"`
	NewSourceOnly   int                 `json:"newSourceOnly"`
	NewTargetOnly   int                 `json:"newTargetOnly"`
	IssuesCount     int                 `json:"issuesCount"`
	IssuesTruncated bool                `json:"issuesTruncated"`
	Issues          []DurableAuditIssue `json:"issues"`
	Pending         []PendingCopy       `json:"pending"`
	SafeToRun       bool                `json:"safeToRun"`
}

// AuditDurableState allows inspecting a pending or otherwise inconsistent
// state and its current folder contents. It DOES NOT clear pending state,
// mutate files, reconcile histories, or authorize a restart automatically.
func AuditDurableState(left, right, filename string, excludes []string) (DurableAudit, error) {
	a := DurableAudit{Mode: "durable-sync-state-audit", ReadOnly: true, Issues: []DurableAuditIssue{}, Pending: []PendingCopy{}}
	s, err := ValidateDurableState(left, right, filename, excludes)
	if err != nil {
		return a, err
	}
	a.Version = s.Version
	a.Generation = s.Generation
	a.Phase = s.Phase
	a.KnownFiles = len(s.Files)
	a.Pending = append(a.Pending, s.Pending...)
	p, err := CompareFiltered(left, right, excludes)
	if err != nil {
		return a, fmt.Errorf("audit inventory failed: %w", err)
	}
	byPath := make(map[string]Change, len(p.Changes))
	for _, change := range p.Changes {
		byPath[change.Path] = change
	}
	known := make(map[string]struct{}, len(s.Files))
	addIssue := func(path, reason string) {
		a.IssuesCount++
		if len(a.Issues) >= MaxDurableAuditIssues {
			a.IssuesTruncated = true
			return
		}
		a.Issues = append(a.Issues, DurableAuditIssue{Path: path, Reason: reason})
	}
	for _, before := range s.Files {
		known[before.Path] = struct{}{}
		current, ok := byPath[before.Path]
		switch {
		case !ok:
			addIssue(before.Path, "previously-shared-missing-both")
		case current.Status == "source-only":
			addIssue(before.Path, "previously-shared-missing-target")
		case current.Status == "target-only":
			addIssue(before.Path, "previously-shared-missing-source")
		case current.Status == "different":
			addIssue(before.Path, "previously-shared-content-diverged")
		case current.Source == nil || current.Source.Size != before.Size || current.Source.SHA256 != before.SHA256:
			addIssue(before.Path, "previously-shared-hash-changed")
		}
	}
	for _, change := range p.Changes {
		if _, wasKnown := known[change.Path]; wasKnown {
			continue
		}
		switch change.Status {
		case "source-only":
			a.NewSourceOnly++
		case "target-only":
			a.NewTargetOnly++
		case "different":
			addIssue(change.Path, "untracked-content-conflict")
		}
	}
	if a.NewSourceOnly+a.NewTargetOnly > MaxAdditions {
		addIssue("", "new-file-count-exceeds-safety-limit")
	}
	var newBytes int64
	for _, change := range p.Changes {
		var f *File
		switch change.Status {
		case "source-only":
			f = change.Source
		case "target-only":
			f = change.Target
		default:
			continue
		}
		if f == nil || f.Size < 0 || f.Size > MaxAdditionBytes-newBytes {
			addIssue("", "new-file-bytes-exceed-safety-limit")
			break
		}
		newBytes += f.Size
	}
	if s.Phase == "pending" {
		addIssue("", "incomplete-copy-batch-requires-manual-review")
	}
	// This is only a read-only snapshot, never permission to delete, overwrite,
	// retry an incomplete batch or trust a hostile mutable directory.
	a.SafeToRun = s.Phase == "ready" && a.IssuesCount == 0
	return a, nil
}
