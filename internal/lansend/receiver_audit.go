package lansend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReceiverDirectoryAudit is read-only. Stage files can contain received
// plaintext after a crash, so this report never reads or deletes their data.
// Names are capped to avoid unbounded or unexpectedly sensitive CLI output.
type ReceiverDirectoryAudit struct {
	Status            string   `json:"status"`
	StageResidueCount int      `json:"stageResidueCount"`
	StageResidues     []string `json:"stageResidues"`
	NamesTruncated    bool     `json:"namesTruncated"`
}

const receiverStagePrefix = ".gcsend-stage-"
const receiverAuditNameLimit = 32

// AuditReceiverDirectory checks an existing real, private receiver folder.
// Files with the reserved staging prefix are never considered valid deliveries.
// The caller decides how to reconcile them; this function is read-only.
func AuditReceiverDirectory(dir string) (ReceiverDirectoryAudit, error) {
	var report ReceiverDirectoryAudit
	st, err := os.Lstat(dir)
	if err != nil {
		return report, fmt.Errorf("inspect receiver folder: %w", err)
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return report, errors.New("receiver directory must be a real private directory (0700)")
	}
	root, err := os.Open(dir)
	if err != nil {
		return report, fmt.Errorf("open receiver folder: %w", err)
	}
	defer root.Close()
	report.StageResidues = []string{}
	for {
		entries, readErr := root.ReadDir(128)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), receiverStagePrefix) {
				continue
			}
			report.StageResidueCount++
			if len(report.StageResidues) < receiverAuditNameLimit {
				report.StageResidues = append(report.StageResidues, entry.Name())
			} else {
				report.NamesTruncated = true
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return report, fmt.Errorf("read receiver entries: %w", readErr)
		}
	}

	if report.StageResidueCount > 0 {
		report.Status = "manual-review-required"
	} else {
		report.Status = "clear"
	}
	return report, nil
}
