package syncplan

import (
	"errors"
	"fmt"
)

// BidirectionalAdditionsResult names the paths that were ACTUALLY committed.
// If Applied is false, the result may contain partial commits after a
// filesystem error; it is never represented as an atomic transaction.
type BidirectionalAdditionsResult struct {
	Mode         string   `json:"mode"`
	Applied      bool     `json:"applied"`
	LeftCreated  []string `json:"leftCreated"`
	RightCreated []string `json:"rightCreated"`
	BytesWritten int64    `json:"bytesWritten"`
	Unchanged    int      `json:"unchanged"`
	Conflicts    int      `json:"conflicts"`
}

// ApplyBidirectionalAdditionsFiltered manually copies only absent regular
// files in either direction. It PREVALIDATES both inventories and refuses any
// divergent same-path contents before writing. Neither existing files nor
// deletions are ever propagated. It reuses the atomic no-overwrite copier and
// its checksum/identity checks, and bounds the TOTAL combined additions to
// 1024 files and 1 GiB (not twice those limits).
//
// Like the existing one-way copier, this is not safe against a hostile peer
// concurrently rewriting parent directories. It is not all-or-nothing; after
// a partial failure its result lists the committed files in each directory.
func ApplyBidirectionalAdditionsFiltered(left, right string, excludes []string) (BidirectionalAdditionsResult, error) {
	result, _, err := applyBidirectionalAdditionsGuarded(left, right, excludes, nil)
	return result, err
}

// applyBidirectionalAdditionsGuarded additionally stops a running foreground
// session when a file previously present on BOTH sides disappears from one.
// This prevents silent resurrection during a session, but the in-memory guard
// is NOT durable across process restarts and is not a deletion policy.
func applyBidirectionalAdditionsGuarded(left, right string, excludes []string, previouslyShared map[string]struct{}) (BidirectionalAdditionsResult, Plan, error) {
	result := BidirectionalAdditionsResult{
		Mode:        "bidirectional-additions-only",
		LeftCreated: []string{}, RightCreated: []string{},
	}
	if err := isolatedRoots(left, right); err != nil {
		return result, Plan{}, err
	}
	plan, err := CompareFiltered(left, right, excludes)
	if err != nil {
		return result, Plan{}, err
	}
	result.Unchanged, result.Conflicts = plan.Identical, plan.Different
	for _, change := range plan.Changes {
		if change.Status == "source-only" || change.Status == "target-only" {
			if _, wasShared := previouslyShared[change.Path]; wasShared {
				result.Conflicts++
				return result, plan, fmt.Errorf("previously shared file %q is missing on one side; manual deletion review required", change.Path)
			}
		}
	}
	result, err = applyBidirectionalPlan(left, right, plan)
	return result, plan, err
}

// applyBidirectionalPlan executes ONLY the plan that was already reviewed and
// journaled, instead of silently re-inventorying and admitting later additions.
// copyOneAtomic independently revalidates each source hash and uses an atomic
// no-overwrite commit. The caller must check the entire final inventory.
func applyBidirectionalPlan(left, right string, plan Plan) (BidirectionalAdditionsResult, error) {
	result := BidirectionalAdditionsResult{Mode: "bidirectional-additions-only", LeftCreated: []string{}, RightCreated: []string{}, Unchanged: plan.Identical, Conflicts: plan.Different}
	var err error
	if plan.Different != 0 {
		return result, fmt.Errorf("refusing bidirectional additions while %d divergent paths exist", plan.Different)
	}
	if plan.SourceOnly > MaxAdditions-plan.TargetOnly {
		return result, fmt.Errorf("bidirectional additions exceed %d-file safety limit", MaxAdditions)
	}
	var total int64
	for _, c := range plan.Changes {
		var f *File
		switch c.Status {
		case "source-only":
			f = c.Source
		case "target-only":
			f = c.Target
		}
		if f == nil {
			continue
		}
		if f.Size < 0 || f.Size > MaxAdditionBytes-total {
			return result, fmt.Errorf("bidirectional additions exceed %d-byte safety limit", MaxAdditionBytes)
		}
		total += f.Size
	}
	// A deterministic sorted traversal also ensures partial commit reporting
	// can be compared to the originally reviewed read-only plan.
	for _, c := range plan.Changes {
		var n int64
		var committed bool
		switch c.Status {
		case "source-only":
			n, committed, err = copyOneAtomic(left, right, c)
			if committed {
				result.RightCreated = append(result.RightCreated, c.Path)
			}
		case "target-only":
			reverse := Change{Path: c.Path, Status: "source-only", Source: c.Target}
			n, committed, err = copyOneAtomic(right, left, reverse)
			if committed {
				result.LeftCreated = append(result.LeftCreated, c.Path)
			}
		default:
			continue
		}
		if committed {
			result.BytesWritten += n
		}
		if err != nil {
			return result, fmt.Errorf("bidirectional additions stopped at %q: %w", c.Path, err)
		}
	}
	if len(result.LeftCreated)+len(result.RightCreated) > MaxAdditions {
		return result, errors.New("internal additions limit exceeded")
	}
	result.Applied = true
	return result, nil
}
