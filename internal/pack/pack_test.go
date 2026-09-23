package pack

import (
	"os"
	"path/filepath"
	"testing"
)

func tempPack(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(sub, name, body string) {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
		if err := os.WriteFile(filepath.Join(dir, sub, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("prompt-injection", "pi-001.yaml", "id: pi-001\npayload: a\n")
	write("jailbreak", "jb-001.yaml", "id: jb-001\npayload: b\n")
	return dir
}

func TestComputeDeterministic(t *testing.T) {
	dir := tempPack(t)
	a, err := Compute(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compute(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest || a.Digest == "" {
		t.Fatalf("digest not deterministic: %q vs %q", a.Digest, b.Digest)
	}
	if len(a.Files) != 2 {
		t.Fatalf("want 2 files, got %d", len(a.Files))
	}
	// Files are sorted by path.
	if a.Files[0].Path != "jailbreak/jb-001.yaml" {
		t.Errorf("files not sorted: %q", a.Files[0].Path)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := tempPack(t)
	lock, _ := Compute(dir)
	if err := WriteLock(dir, lock); err != nil {
		t.Fatal(err)
	}

	// Unchanged -> OK.
	rl, _ := ReadLock(dir)
	res, err := Verify(dir, rl, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("clean pack should verify OK: %+v", res)
	}

	// Modify a file -> CHANGED.
	if err := os.WriteFile(filepath.Join(dir, "jailbreak", "jb-001.yaml"), []byte("id: jb-001\npayload: TAMPERED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _ = Verify(dir, rl, "")
	if res.OK || len(res.Changed) != 1 {
		t.Fatalf("modified file should be CHANGED, got %+v", res)
	}

	// Add a file -> ADDED.
	_ = os.WriteFile(filepath.Join(dir, "extra.yaml"), []byte("id: x\npayload: z\n"), 0o644)
	res, _ = Verify(dir, rl, "")
	if res.OK || len(res.Added) != 1 {
		t.Fatalf("new file should be ADDED, got %+v", res)
	}

	// Remove a file -> REMOVED.
	_ = os.Remove(filepath.Join(dir, "prompt-injection", "pi-001.yaml"))
	res, _ = Verify(dir, rl, "")
	if !containsStr(res.Removed, "prompt-injection/pi-001.yaml") {
		t.Fatalf("removed file should be REMOVED, got %+v", res)
	}
}

func TestVerifyDetectsLockTamper(t *testing.T) {
	dir := tempPack(t)
	lock, _ := Compute(dir)
	// Tamper the lock's recorded hash without updating the digest.
	lock.Files[0].SHA256 = "00" + lock.Files[0].SHA256[2:]
	res, err := Verify(dir, lock, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.DigestMismatch || res.OK {
		t.Fatalf("tampered lock should fail digest check: %+v", res)
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	dir := tempPack(t)
	privB64, pubB64, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := PrivateKeyFromBase64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	lock, _ := Compute(dir)
	Sign(lock, priv)
	_ = WriteLock(dir, lock)

	rl, _ := ReadLock(dir)

	// Pinned to the correct key -> valid.
	res, err := Verify(dir, rl, pubB64)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.SignatureValid {
		t.Fatalf("correct key should verify: %+v", res)
	}

	// Pinned to a different key -> invalid (authenticity failure).
	_, otherPub, _ := GenerateKey()
	res, _ = Verify(dir, rl, otherPub)
	if res.OK || res.SignatureValid {
		t.Fatalf("wrong pinned key must fail: %+v", res)
	}

	// Tamper a file after signing -> integrity fails even with the right key.
	_ = os.WriteFile(filepath.Join(dir, "jailbreak", "jb-001.yaml"), []byte("id: jb-001\npayload: TAMPERED\n"), 0o644)
	res, _ = Verify(dir, rl, pubB64)
	if res.OK {
		t.Fatalf("tampered signed pack must fail: %+v", res)
	}
}

// TestCorePackMatchesLock guards the shipped pack: packs/core must verify
// against its committed lock. If this fails after editing attacks, regenerate
// the lock with `momus pack lock packs/core --name momus-core --pack-version X`.
func TestCorePackMatchesLock(t *testing.T) {
	const dir = "../../packs/core"
	lock, err := ReadLock(dir)
	if err != nil {
		t.Fatalf("read core lock: %v", err)
	}
	res, err := Verify(dir, lock, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("core pack does not match its lock (re-run `momus pack lock packs/core`): changed=%v added=%v removed=%v digestMismatch=%v",
			res.Changed, res.Added, res.Removed, res.DigestMismatch)
	}
}

// TestComputeFSMatchesComputeOnDisk pins a load-bearing invariant: the embedded
// (fs.FS) and on-disk hashers must produce the SAME relative paths and digest.
// If they diverge, `momus pack verify` would pass on a checkout and fail on an
// installed binary (or vice versa) for the identical pack.
func TestComputeFSMatchesComputeOnDisk(t *testing.T) {
	onDisk, err := Compute("../../packs/core")
	if err != nil {
		t.Fatal(err)
	}
	viaFS, err := ComputeFS(os.DirFS("../.."), "packs/core")
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.Digest != viaFS.Digest {
		t.Fatalf("digest mismatch: on-disk %s vs fs.FS %s", onDisk.Digest, viaFS.Digest)
	}
	if len(onDisk.Files) != len(viaFS.Files) {
		t.Fatalf("file count mismatch: %d vs %d", len(onDisk.Files), len(viaFS.Files))
	}
	for i := range onDisk.Files {
		if onDisk.Files[i] != viaFS.Files[i] {
			t.Fatalf("entry %d differs: %+v vs %+v", i, onDisk.Files[i], viaFS.Files[i])
		}
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
