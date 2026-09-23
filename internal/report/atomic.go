package report

import (
	"io"
	"os"
	"path/filepath"
)

// atomicWrite writes to a temp file in the target's directory, checks the close
// error, then renames into place. A failed write therefore never clobbers a
// previous file or reports success on a truncated one.
func atomicWrite(path string, write func(io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".momus-report-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = write(tmp); err != nil {
		return err
	}
	// CreateTemp makes the file 0600; reports are meant to be read by other
	// tooling (CI artifact upload, a browser, a reviewer), so widen to the usual
	// 0644 before publishing it.
	if err = tmp.Chmod(0o644); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
