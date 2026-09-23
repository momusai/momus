// Package pack provides integrity locking and signing for Momus attack packs.
//
// A lock file (momus-pack.lock.json at the pack root) records a SHA-256 for every
// attack file plus an overall digest, so `momus pack verify` can detect any
// modified, added, or removed attack. The digest may additionally be signed with
// an Ed25519 key so a publisher's packs can be authenticated against a pinned
// public key. Everything uses the Go standard library — no external dependencies.
package pack

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/momus-ai/momus/internal/mal"
)

// LockFileName is the integrity manifest written at a pack's root.
const LockFileName = "momus-pack.lock.json"

// FileHash is one attack file and its content hash.
type FileHash struct {
	Path   string `json:"path"`   // pack-relative, forward-slash separated
	SHA256 string `json:"sha256"` // hex
}

// Lock is a pack's integrity manifest.
type Lock struct {
	Name      string     `json:"name,omitempty"`
	Version   string     `json:"version,omitempty"`
	Files     []FileHash `json:"files"`
	Digest    string     `json:"digest"`               // hex sha256 over the sorted file list
	Signature string     `json:"signature,omitempty"`  // base64 Ed25519 signature over Digest
	PublicKey string     `json:"public_key,omitempty"` // base64 Ed25519 public key of the signer
}

// ParseLock decodes a lock file's bytes (used for the lock embedded in the binary).
func ParseLock(b []byte) (*Lock, error) {
	var l Lock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("parse lock: %w", err)
	}
	return &l, nil
}

// ComputeFS hashes a pack inside any fs.FS (an embed.FS, say), so the integrity
// check works for a distributed binary and not only a git checkout.
func ComputeFS(fsys fs.FS, root string) (*Lock, error) {
	var files []FileHash
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := path.Base(p)
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		if mal.IsReservedPackFile(name) {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
		sum := sha256.Sum256(b)
		files = append(files, FileHash{Path: rel, SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return &Lock{Files: files, Digest: digestOf(files)}, nil
}

// VerifyFS compares a pack inside an fs.FS against lock.
func VerifyFS(fsys fs.FS, root string, lock *Lock) (*VerifyResult, error) {
	cur, err := ComputeFS(fsys, root)
	if err != nil {
		return nil, err
	}
	return compare(cur, lock), nil
}

// Compute walks dir for attack files (skipping reserved pack files) and returns
// a Lock with per-file hashes and an overall digest. It does not sign.
func Compute(dir string) (*Lock, error) {
	var files []FileHash
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		if mal.IsReservedPackFile(name) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		files = append(files, FileHash{Path: filepath.ToSlash(rel), SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return &Lock{Files: files, Digest: digestOf(files)}, nil
}

// digestOf is a deterministic hash over the sorted (path, sha256) pairs.
func digestOf(files []FileHash) string {
	h := sha256.New()
	for _, f := range files {
		// hash.Hash.Write never errors; blank-assign to satisfy linters.
		_, _ = io.WriteString(h, f.Path+"\x00"+f.SHA256+"\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyResult reports how a pack differs from its lock.
type VerifyResult struct {
	OK               bool
	Changed          []string // hash differs from the lock
	Added            []string // present on disk, absent from the lock
	Removed          []string // in the lock, absent on disk
	DigestMismatch   bool     // the lock's own digest does not match its file list
	SignatureChecked bool
	SignatureValid   bool
	SignerKey        string // base64 public key the signature was checked against
}

// Verify recomputes the pack's hashes and compares them to lock. If the lock
// carries a signature it is checked; when trustedPubKey is non-empty the
// signature must verify against THAT key (authenticity), otherwise it is only
// checked against the embedded key (integrity/self-consistency).
func Verify(dir string, lock *Lock, trustedPubKey string) (*VerifyResult, error) {
	cur, err := Compute(dir)
	if err != nil {
		return nil, err
	}
	res := compare(cur, lock)
	if lock.Signature != "" {
		res.SignatureChecked = true
		key := lock.PublicKey
		if trustedPubKey != "" {
			// Authenticity: the signature must verify under the pinned key AND the
			// lock must actually be signed by that key.
			key = trustedPubKey
			if trustedPubKey != lock.PublicKey {
				res.SignatureValid = false
				res.SignerKey = key
				res.OK = false
				return res, nil
			}
		}
		ok, err := verifySignature(lock, key)
		if err != nil {
			return nil, err
		}
		res.SignatureValid = ok
		res.SignerKey = key
		if !ok {
			res.OK = false
		}
	}
	return res, nil
}

// compare diffs a freshly computed lock against a stored one.
func compare(cur, lock *Lock) *VerifyResult {
	res := &VerifyResult{}

	lockMap := make(map[string]string, len(lock.Files))
	for _, f := range lock.Files {
		lockMap[f.Path] = f.SHA256
	}
	curMap := make(map[string]string, len(cur.Files))
	for _, f := range cur.Files {
		curMap[f.Path] = f.SHA256
	}
	for p, h := range curMap {
		if lh, ok := lockMap[p]; !ok {
			res.Added = append(res.Added, p)
		} else if lh != h {
			res.Changed = append(res.Changed, p)
		}
	}
	for p := range lockMap {
		if _, ok := curMap[p]; !ok {
			res.Removed = append(res.Removed, p)
		}
	}
	sort.Strings(res.Changed)
	sort.Strings(res.Added)
	sort.Strings(res.Removed)

	// The lock's stated digest must match its own file list, or the lock itself
	// was tampered with.
	res.DigestMismatch = lock.Digest != digestOf(lock.Files)

	res.OK = len(res.Changed) == 0 && len(res.Added) == 0 && len(res.Removed) == 0 && !res.DigestMismatch
	return res
}

// Sign signs lock.Digest with priv and stores the signature + public key on lock.
func Sign(lock *Lock, priv ed25519.PrivateKey) {
	sig := ed25519.Sign(priv, []byte(lock.Digest))
	lock.Signature = base64.StdEncoding.EncodeToString(sig)
	lock.PublicKey = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// VerifySignature checks lock.Signature against a public key; an empty key means
// "use the key embedded in the lock" (integrity only, not authenticity).
func VerifySignature(lock *Lock, pubB64 string) (bool, error) {
	if pubB64 == "" {
		pubB64 = lock.PublicKey
	}
	if pubB64 != lock.PublicKey {
		return false, nil // pinned to a different key than the one that signed it
	}
	return verifySignature(lock, pubB64)
}

func verifySignature(lock *Lock, pubB64 string) (bool, error) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return false, fmt.Errorf("bad public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(lock.Signature)
	if err != nil {
		return false, fmt.Errorf("bad signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(lock.Digest), sig), nil
}

// GenerateKey returns a fresh Ed25519 keypair, base64-encoded.
func GenerateKey() (privB64, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// PrivateKeyFromBase64 decodes a base64 Ed25519 private key.
func PrivateKeyFromBase64(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("bad private key encoding: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// WriteLock writes the lock as pretty JSON to dir/momus-pack.lock.json.
func WriteLock(dir string, lock *Lock) error {
	b, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, LockFileName), append(b, '\n'), 0o644)
}

// ReadLock reads dir/momus-pack.lock.json.
func ReadLock(dir string) (*Lock, error) {
	b, err := os.ReadFile(filepath.Join(dir, LockFileName))
	if err != nil {
		return nil, err
	}
	var l Lock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("parse lock: %w", err)
	}
	return &l, nil
}
