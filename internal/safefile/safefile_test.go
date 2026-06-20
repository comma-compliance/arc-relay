package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadWriteRoundTrip(t *testing.T) {
	base := t.TempDir()
	if err := WriteFile(base, "config.json", []byte("hello"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadFile(base, "config.json")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestWriteCreatesNestedUnderExistingParent(t *testing.T) {
	base := t.TempDir()
	// Parent must already exist for a confined write — mirror caller behavior.
	if err := os.MkdirAll(filepath.Join(base, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(base, ".codex/config.toml", []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile nested: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, ".codex", "config.toml")); err != nil {
		t.Fatalf("expected file written: %v", err)
	}
}

func TestRejectsAbsoluteRel(t *testing.T) {
	base := t.TempDir()
	abs := filepath.Join(t.TempDir(), "outside.json")
	if err := WriteFile(base, abs, []byte("x"), 0600); err == nil {
		t.Fatal("expected WriteFile to reject absolute rel path")
	}
	if _, err := ReadFile(base, abs); err == nil {
		t.Fatal("expected ReadFile to reject absolute rel path")
	}
}

func TestRejectsTraversalEscape(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{"../escape.json", "a/../../escape.json", ".."} {
		if _, err := Path(base, rel); err == nil {
			t.Fatalf("expected %q to be rejected as traversal", rel)
		}
	}
}

func TestAllowsInternalDotDot(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "a"), 0700); err != nil {
		t.Fatal(err)
	}
	// a/../config.json normalizes back to config.json — inside base, must be allowed.
	p, err := Path(base, "a/../config.json")
	if err != nil {
		t.Fatalf("internal .. that stays in base should be allowed: %v", err)
	}
	if p != filepath.Join(base, "config.json") {
		t.Fatalf("unexpected resolved path: %q", p)
	}
}

func TestRejectsSymlinkLeafEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on Windows CI")
	}
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte("preexisting"), 0600); err != nil {
		t.Fatal(err)
	}
	// Plant a symlink inside base that points outside it.
	link := filepath.Join(base, ".mcp.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	// A confined write must refuse to follow the leaf symlink (which would
	// clobber the outside file with a token-bearing config).
	if err := WriteFile(base, ".mcp.json", []byte("token"), 0600); err == nil {
		t.Fatal("expected WriteFile to refuse following a leaf symlink")
	}
	// The outside file must be untouched.
	got, _ := os.ReadFile(outside)
	if string(got) != "preexisting" {
		t.Fatalf("outside file was modified through symlink: %q", got)
	}
	// A confined read must likewise refuse.
	if _, err := ReadFile(base, ".mcp.json"); err == nil {
		t.Fatal("expected ReadFile to refuse following a leaf symlink")
	}
}

func TestRejectsSymlinkedParentEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on Windows CI")
	}
	base := t.TempDir()
	outsideDir := t.TempDir()
	// base/.claude -> outsideDir, then write base/.claude/CLAUDE.md should be
	// rejected because the parent resolves outside base.
	if err := os.Symlink(outsideDir, filepath.Join(base, ".claude")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(base, ".claude/CLAUDE.md", []byte("x"), 0600); err == nil {
		t.Fatal("expected WriteFile to reject a symlinked parent escaping base")
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "CLAUDE.md")); err == nil {
		t.Fatal("file leaked outside base through symlinked parent")
	}
}

func TestReadMissingFilePropagatesNotExist(t *testing.T) {
	base := t.TempDir()
	_, err := ReadFile(base, "config.json")
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist for missing file, got %v", err)
	}
}
