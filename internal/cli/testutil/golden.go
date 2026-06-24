package testutil

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

// GoldenFile compares got against testdata/golden/<name>. If the -update flag
// is set, it writes got to the golden file instead.
func GoldenFile(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join("testdata", "golden", name)

	if *update {
		err := os.MkdirAll(filepath.Dir(golden), 0750)
		if err != nil {
			t.Fatalf("failed to create golden dir: %v", err)
		}
		err = os.WriteFile(golden, got, 0600)
		if err != nil {
			t.Fatalf("failed to write golden file: %v", err)
		}
		return
	}

	expected, err := os.ReadFile(golden) // #nosec G304 — test-only helper; golden is "testdata/golden/" + a test-supplied constant name.
	if err != nil {
		t.Fatalf("failed to read golden file %s (run with -update to create): %v", golden, err)
	}

	if string(got) != string(expected) {
		t.Errorf("output does not match golden file %s\n--- got ---\n%s\n--- expected ---\n%s",
			golden, string(got), string(expected))
	}
}
