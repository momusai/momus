package mal

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// IsReservedPackFile reports whether a file name is a pack-level file (manifest
// or integrity lock) rather than an attack, so the pack walkers skip it.
func IsReservedPackFile(name string) bool {
	switch name {
	case "momus-pack.yaml", "momus-pack.yml", "momus-pack.lock.json":
		return true
	default:
		return false
	}
}

// LoadPack walks a directory tree on disk and returns every well-formed MAL
// attack it finds. Malformed files are logged and skipped rather than aborting.
func LoadPack(root string) ([]Attack, error) {
	a, _, err := LoadPackDetailed(root)
	return a, err
}

// LoadPackDetailed is LoadPack plus the list of files it had to skip. The scan
// path uses this: a pack where half the attacks fail to parse must not quietly
// scan the survivors and report a clean gate pass, so the caller needs to know
// that something was dropped rather than reading it in a log line.
func LoadPackDetailed(root string) ([]Attack, []Skipped, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("pack %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("pack %s is not a directory", root)
	}
	attacks, skipped, err := LoadPackFSDetailed(os.DirFS(root), ".")
	// os.DirFS roots the walk at the pack directory, so the paths that come back
	// are relative to it and drop the directory itself. Put it back: Source has
	// to be usable from the repo root, because that is what SARIF locations and
	// GitHub code scanning resolve against.
	for i := range attacks {
		attacks[i].Source = filepath.ToSlash(filepath.Join(root, attacks[i].Source))
	}
	return attacks, skipped, err
}

// LoadPackFS walks root within fsys and returns every well-formed MAL attack.
// This backs both on-disk packs (os.DirFS) and the pack embedded in the binary
// (embed.FS), so a `go install`-ed or npx-fetched momus scans out of the box.
func LoadPackFS(fsys fs.FS, root string) ([]Attack, error) {
	a, _, err := LoadPackFSDetailed(fsys, root)
	return a, err
}

// LoadPackFSDetailed is LoadPackFS plus the files it had to skip.
func LoadPackFSDetailed(fsys fs.FS, root string) ([]Attack, []Skipped, error) {
	var attacks []Attack
	var skipped []Skipped
	seen := map[string]string{} // attack id -> first path, to warn on duplicates
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		if IsReservedPackFile(path.Base(p)) {
			return nil // pack manifest / lock file, not an attack
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		a, err := ParseAttack(data, p)
		if err != nil {
			// Reported to the caller rather than logged: the scan path turns
			// this into a hard error, and logging it too just prints it twice.
			skipped = append(skipped, Skipped{Path: p, Err: err})
			return nil
		}
		if prev, dup := seen[a.ID]; dup {
			slog.Warn("duplicate attack id", "id", a.ID, "path", p, "first", prev)
		} else {
			seen[a.ID] = p
		}
		attacks = append(attacks, *a)
		return nil
	})
	return attacks, skipped, err
}

// Skipped is an attack file the loader could not use.
type Skipped struct {
	Path string
	Err  error
}
