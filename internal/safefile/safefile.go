// Package safefile provides base-directory-confined file access.
//
// arc-sync reads and writes credential-bearing config files (.mcp.json,
// .codex/config.toml, config.json, state.json) inside whatever project or
// user-config directory the CLI is pointed at. Those files can contain
// "Authorization: Bearer <token>" headers. If an attacker can plant a symlink
// at one of those paths — for example, a hostile project repository a user
// clones and then runs arc-sync inside — a naive os.WriteFile would follow the
// link and write the token to an arbitrary location outside the project.
//
// The helpers here confine all access to an explicit base directory: the
// relative sub-path may not be absolute, may not escape the base with "..",
// and neither the resolved parent directory nor the final component may be a
// symlink that points outside the base. This is defense-in-depth for a CLI
// that already runs with the user's own privileges; the goal is to stop a
// malicious *directory tree* from redirecting a token write, not to defend
// against an attacker who already controls the user's account.
//
// Confinement is best-effort against a concurrent local attacker (a
// check-then-open sequence is inherently TOCTOU-prone), but it deterministically
// rejects the static symlink-redirect case, which is the realistic threat here.
package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolve validates that rel stays within base and returns the cleaned absolute
// path of the target. It rejects absolute rel paths and any ".." traversal that
// would escape base. It does not touch the filesystem.
func resolve(base, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("safefile: empty relative path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("safefile: %q is absolute, must be relative to base", rel)
	}
	// On Windows a path like `C:foo` is not reported absolute by IsAbs but still
	// carries a volume; reject any volume-qualified rel so it can never anchor
	// outside base. (Current callers pass constants, but keep the guard.)
	if filepath.VolumeName(rel) != "" {
		return "", fmt.Errorf("safefile: %q is volume-qualified, must be relative to base", rel)
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("safefile: resolving base %q: %w", base, err)
	}
	absBase = filepath.Clean(absBase)

	target := filepath.Clean(filepath.Join(absBase, rel))

	// Re-derive the relationship from the cleaned paths: rel must not climb out
	// of base. filepath.Rel handles "." and nested paths correctly across
	// platforms (including Windows volume/case semantics for same-volume paths).
	within, err := filepath.Rel(absBase, target)
	if err != nil {
		return "", fmt.Errorf("safefile: %q escapes base %q", rel, base)
	}
	if within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("safefile: %q escapes base %q", rel, base)
	}

	return target, nil
}

// checkNoSymlinkEscape verifies that the already-existing portion of target does
// not leave base via a symlink. It evaluates symlinks on the deepest existing
// ancestor of target (the file itself if it exists, otherwise its parent
// directory, walking up as needed) and confirms the real path is still inside
// the real base. A write target that does not yet exist is allowed as long as
// its existing parent resolves inside base and the final component, if present,
// is not itself a symlink.
func checkNoSymlinkEscape(absBase, target string) error {
	realBase, err := filepath.EvalSymlinks(absBase)
	if err != nil {
		// Base must exist and resolve for confinement to mean anything; callers
		// create it (MkdirAll) before writing.
		return fmt.Errorf("safefile: resolving base %q: %w", absBase, err)
	}
	realBase = filepath.Clean(realBase)

	// If the final component already exists, reject it being a symlink outright —
	// we never want to follow a link at the leaf for a confined write/read.
	if info, lerr := os.Lstat(target); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("safefile: refusing to follow symlink at %q", target)
		}
	}

	// Find the deepest ancestor that exists and resolve it. EvalSymlinks fails on
	// a path whose leaf does not exist yet, which is the normal case for a fresh
	// write, so we walk up to the nearest existing directory.
	probe := target
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			resolved = filepath.Clean(resolved)
			if resolved != realBase &&
				!strings.HasPrefix(resolved, realBase+string(filepath.Separator)) {
				return fmt.Errorf("safefile: %q resolves outside base %q (symlink escape)", target, absBase)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("safefile: resolving %q: %w", probe, err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			// Walked to the filesystem root without finding an existing ancestor.
			return fmt.Errorf("safefile: no existing ancestor for %q under base %q", target, absBase)
		}
		probe = parent
	}
}

// confinedPath validates rel against base and verifies no symlink escape, then
// returns the concrete path to operate on.
//
// If base itself does not exist, confinement is moot (there is nothing to
// escape into) and the second return value is false, signaling callers to fall
// back to a raw os call against target so the canonical *PathError /
// os.IsNotExist behavior is preserved for not-yet-initialized directories.
func confinedPath(base, rel string) (target string, confined bool, err error) {
	target, err = resolve(base, rel)
	if err != nil {
		return "", false, err
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", false, fmt.Errorf("safefile: resolving base %q: %w", base, err)
	}
	absBase = filepath.Clean(absBase)
	if _, statErr := os.Lstat(absBase); statErr != nil {
		if os.IsNotExist(statErr) {
			return target, false, nil
		}
		return "", false, fmt.Errorf("safefile: resolving base %q: %w", absBase, statErr)
	}
	if err := checkNoSymlinkEscape(absBase, target); err != nil {
		return "", false, err
	}
	return target, true, nil
}

// ReadFile reads base/rel, confined to base. rel must be a relative path that
// does not escape base, and the resolved path must not cross a symlink out of
// base.
func ReadFile(base, rel string) ([]byte, error) {
	target, _, err := confinedPath(base, rel)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(target) // #nosec G304 — target is confined to base by confinedPath above (or base is absent, yielding a canonical not-exist error).
}

// WriteFile writes data to base/rel with the given perm, confined to base. The
// existing parent directory must already resolve inside base (callers create it
// with MkdirAll first); the final component must not be a pre-existing symlink.
func WriteFile(base, rel string, data []byte, perm os.FileMode) error {
	target, _, err := confinedPath(base, rel)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, perm) // #nosec G304 — target is confined to base by confinedPath above.
}

// Open opens base/rel for reading, confined to base.
func Open(base, rel string) (*os.File, error) {
	target, _, err := confinedPath(base, rel)
	if err != nil {
		return nil, err
	}
	return os.Open(target) // #nosec G304 — target is confined to base by confinedPath above (or base is absent, yielding a canonical not-exist error).
}

// Path validates that base/rel is confined to base and returns the resolved
// path without opening it. Use this for callers that need the path for an
// os.OpenFile with custom flags (e.g. append) but still want confinement.
func Path(base, rel string) (string, error) {
	target, _, err := confinedPath(base, rel)
	return target, err
}
