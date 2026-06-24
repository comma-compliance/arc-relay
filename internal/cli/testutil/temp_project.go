package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TempProject creates a temp directory and optionally writes an .mcp.json file
// with the given content. Returns the project directory path.
func TempProject(t *testing.T, mcpJSON string) string {
	t.Helper()
	dir := t.TempDir()
	if mcpJSON != "" {
		err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(mcpJSON), 0644)
		if err != nil {
			t.Fatalf("failed to write .mcp.json: %v", err)
		}
	}
	return dir
}

// TempProjectWithGit creates a temp directory with a .git directory (to simulate
// a git repo) and optionally writes .mcp.json and .gitignore files.
func TempProjectWithGit(t *testing.T, mcpJSON, gitignore string) string {
	t.Helper()
	dir := TempProject(t, mcpJSON)
	err := os.Mkdir(filepath.Join(dir, ".git"), 0755)
	if err != nil {
		t.Fatalf("failed to create .git dir: %v", err)
	}
	if gitignore != "" {
		err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignore), 0644)
		if err != nil {
			t.Fatalf("failed to write .gitignore: %v", err)
		}
	}
	return dir
}

// TempConfigDir creates a temp directory suitable for use as the arc-sync
// config directory and returns the path.
func TempConfigDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// WriteFile is a test helper that writes content to a file path, creating
// parent directories as needed.
func WriteFile(t *testing.T, path, content string) {
	t.Helper()
	err := os.MkdirAll(filepath.Dir(path), 0750)
	if err != nil {
		t.Fatalf("failed to create parent dirs for %s: %v", path, err)
	}
	err = os.WriteFile(path, []byte(content), 0600)
	if err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}
