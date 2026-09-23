package momus

import (
	"testing"

	"github.com/momus-ai/momus/internal/mal"
)

// TestEmbeddedCorePackMatchesDisk ensures the pack embedded in the binary loads
// and contains exactly the same attacks as packs/core on disk — so a go install /
// npx / release binary scans identically to running from the repo.
func TestEmbeddedCorePackMatchesDisk(t *testing.T) {
	embedded, err := mal.LoadPackFS(CorePack, CorePackRoot)
	if err != nil {
		t.Fatalf("load embedded pack: %v", err)
	}
	if len(embedded) == 0 {
		t.Fatal("embedded pack is empty")
	}
	disk, err := mal.LoadPack("packs/core")
	if err != nil {
		t.Fatalf("load disk pack: %v", err)
	}
	if len(embedded) != len(disk) {
		t.Fatalf("embedded pack has %d attacks, disk has %d", len(embedded), len(disk))
	}
}
