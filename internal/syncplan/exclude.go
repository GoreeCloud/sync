package syncplan

import (
	"fmt"
	"path"
	"strings"
)

// ValidateExclude validates a deliberately small opt-in exclude language:
// - *.tmp matches that basename in any directory
// - build/*.o matches paths relative to a compared root
// - private/** matches that directory and its descendants
// This intentionally does not claim Syncthing .stignore compatibility.
func ValidateExclude(pattern string) error {
	if pattern == "" || strings.HasPrefix(pattern, "/") || strings.Contains(pattern, "\\") ||
		pattern == "." || strings.HasPrefix(pattern, "../") || pattern == ".." ||
		strings.Contains(pattern, "/../") || strings.HasSuffix(pattern, "/..") ||
		strings.Contains(pattern, "//") || strings.HasPrefix(pattern, "./") ||
		strings.HasSuffix(pattern, "/") {
		return fmt.Errorf("invalid exclude pattern %q", pattern)
	}
	check := pattern
	if strings.HasSuffix(check, "/**") {
		check = strings.TrimSuffix(check, "/**")
		if check == "" || strings.ContainsAny(check, "*?[]") {
			return fmt.Errorf("recursive exclude must name a literal directory: %q", pattern)
		}
	} else if strings.Contains(pattern, "**") {
		return fmt.Errorf("only trailing /** recursive patterns supported: %q", pattern)
	}
	if path.Clean(check) != check {
		return fmt.Errorf("exclude path must be canonical: %q", pattern)
	}
	if _, err := path.Match(check, "test"); err != nil {
		return fmt.Errorf("invalid exclude glob %q: %w", pattern, err)
	}
	return nil
}

func shouldExclude(relative string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(p, "/**") {
			root := strings.TrimSuffix(p, "/**")
			if relative == root || strings.HasPrefix(relative, root+"/") {
				return true
			}
			continue
		}
		candidate := relative
		if !strings.Contains(p, "/") {
			candidate = path.Base(relative)
		}
		matches, _ := path.Match(p, candidate)
		if matches {
			return true
		}
	}
	return false
}

func checkExcludes(patterns []string) error {
	if len(patterns) > 64 {
		return fmt.Errorf("at most 64 excludes allowed")
	}
	for _, pattern := range patterns {
		if err := ValidateExclude(pattern); err != nil {
			return err
		}
	}
	return nil
}
