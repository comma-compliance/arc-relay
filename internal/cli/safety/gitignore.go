package safety

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Warning represents a safety warning about file configuration.
type Warning struct {
	Level   string // "info", "warn"
	Message string
	Fix     string // suggested command to fix the issue
}

// FileScope classifies where a file lives relative to the project.
type FileScope string

const (
	ScopeProject FileScope = "PROJECT" // inside project dir, may be committed
	ScopeUser    FileScope = "USER"    // outside project, user-level config
)

// ClassifyPath returns whether a file path is inside the project directory or
// outside it (user-level config).
func ClassifyPath(filePath, projectDir string) FileScope {
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return ScopeUser
	}
	absProject, err := filepath.Abs(projectDir)
	if err != nil {
		return ScopeUser
	}
	if strings.HasPrefix(absFile, absProject+string(filepath.Separator)) || absFile == absProject {
		return ScopeProject
	}
	return ScopeUser
}

// CheckGitignore checks whether a file is properly gitignored in the given
// project directory. Returns warnings if there are issues.
func CheckGitignore(projectDir, filename string) []Warning {
	var warnings []Warning

	// Check if this is a git repo
	gitDir := filepath.Join(projectDir, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		warnings = append(warnings, Warning{
			Level:   "info",
			Message: "Not a git repo — no .gitignore check needed",
		})
		return warnings
	}

	gitignorePath := filepath.Join(projectDir, ".gitignore")
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		warnings = append(warnings, Warning{
			Level:   "warn",
			Message: fmt.Sprintf("No .gitignore found. %s may contain API keys — consider adding a .gitignore", filename),
			Fix:     fmt.Sprintf("echo '%s' >> .gitignore", filename),
		})
		return warnings
	}

	if isInGitignore(gitignorePath, filename) {
		warnings = append(warnings, Warning{
			Level:   "info",
			Message: fmt.Sprintf("%s is gitignored", filename),
		})
	} else {
		warnings = append(warnings, Warning{
			Level:   "warn",
			Message: fmt.Sprintf("%s is NOT in .gitignore. It contains Bearer tokens that will be committed", filename),
			Fix:     fmt.Sprintf("echo '%s' >> .gitignore", filename),
		})
	}

	return warnings
}

// isInGitignore does a simple check for whether a filename appears as a pattern
// in the .gitignore file. This is a basic check — it doesn't handle negation,
// directory-only patterns, or nested .gitignore files.
func isInGitignore(gitignorePath, filename string) bool {
	// gitignorePath is filepath.Join(projectDir, ".gitignore") built by the
	// caller from a constant filename; this is a read-only scan for a gitignore
	// entry (no credentials read or written), so it is confined by construction.
	f, err := os.Open(gitignorePath) // #nosec G304 — projectDir + constant ".gitignore"; read-only gitignore scan.
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Check for exact match or common patterns
		if line == filename || line == "/"+filename || line == filename+"/" {
			return true
		}
	}
	return false
}

// PlannedChange describes a file that will be modified during a sync operation.
type PlannedChange struct {
	Path        string
	Description string
	Scope       FileScope
}

// FormatChangeSummary produces a human-readable summary of planned changes,
// grouped by scope. Returns the formatted string.
func FormatChangeSummary(changes []PlannedChange, projectDir string) string {
	var projectChanges, userChanges []PlannedChange

	for _, c := range changes {
		switch c.Scope {
		case ScopeProject:
			projectChanges = append(projectChanges, c)
		case ScopeUser:
			userChanges = append(userChanges, c)
		}
	}

	var b strings.Builder
	b.WriteString("arc-sync: planning changes\n\n")

	if len(projectChanges) > 0 {
		b.WriteString("  PROJECT FILES (committed to git):\n")
		for _, c := range projectChanges {
			rel, err := filepath.Rel(projectDir, c.Path)
			if err != nil {
				rel = c.Path
			}
			fmt.Fprintf(&b, "    ✎  %s  ← %s\n", rel, c.Description)
		}
		b.WriteString("\n")
	}

	if len(userChanges) > 0 {
		b.WriteString("  USER FILES (outside project, not in git):\n")
		for _, c := range userChanges {
			fmt.Fprintf(&b, "    ✎  %s  ← %s\n", c.Path, c.Description)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// FormatWarnings produces a human-readable summary of warnings.
func FormatWarnings(warnings []Warning) string {
	var b strings.Builder
	for _, w := range warnings {
		switch w.Level {
		case "warn":
			fmt.Fprintf(&b, "  ⚠  %s\n", w.Message)
			if w.Fix != "" {
				fmt.Fprintf(&b, "     Fix: %s\n", w.Fix)
			}
		case "info":
			fmt.Fprintf(&b, "  ✓  %s\n", w.Message)
		}
	}
	return b.String()
}
