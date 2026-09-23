package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	momus "github.com/momus-ai/momus"
	"github.com/momus-ai/momus/internal/pack"
)

func newPackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Manage attack-pack integrity: lock, verify, sign, keygen",
	}
	cmd.AddCommand(newPackLockCmd(), newPackVerifyCmd(), newPackSignCmd(), newPackKeygenCmd())
	return cmd
}

func newPackLockCmd() *cobra.Command {
	var name, packVersion string
	cmd := &cobra.Command{
		Use:   "lock <pack-dir>",
		Short: "Write an integrity lock (per-file SHA-256 + digest) for a pack",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			lock, err := pack.Compute(dir)
			if err != nil {
				return err
			}
			// Preserve name/version and any existing signature only when the
			// content digest is unchanged; otherwise a re-lock invalidates the sig.
			if existing, err := pack.ReadLock(dir); err == nil {
				lock.Name, lock.Version = existing.Name, existing.Version
				if existing.Digest == lock.Digest {
					lock.Signature, lock.PublicKey = existing.Signature, existing.PublicKey
				}
			}
			if name != "" {
				lock.Name = name
			}
			if packVersion != "" {
				lock.Version = packVersion
			}
			if err := pack.WriteLock(dir, lock); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Locked %d files in %s\n  digest: %s\n", len(lock.Files), dir, lock.Digest)
			if lock.Signature != "" {
				fmt.Fprintf(os.Stderr, "  (existing signature preserved)\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "pack name to record in the lock")
	cmd.Flags().StringVar(&packVersion, "pack-version", "", "pack version to record in the lock")
	return cmd
}

func newPackVerifyCmd() *cobra.Command {
	var pubkey string
	cmd := &cobra.Command{
		Use:   "verify [pack-dir]",
		Short: "Verify a pack matches its lock (and signature, if a key is pinned)",
		Long: "Verify a pack matches its lock.\n\n" +
			"With no argument (or when packs/core is absent, e.g. an installed binary),\n" +
			"this verifies the core pack embedded in the binary itself.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			trustedKey, err := resolvePubKey(pubkey)
			if err != nil {
				return err
			}
			// An npx / go install / release user has no packs/core on disk, so the
			// documented integrity check must work against the embedded pack too.
			// Only the DEFAULT path may fall back: a directory the user named that
			// doesn't exist is a mistake, and silently "passing" would be a lie.
			if len(args) == 0 {
				return verifyEmbeddedPack(trustedKey)
			}
			if !dirExists(args[0]) {
				if args[0] == defaultPackDir {
					return verifyEmbeddedPack(trustedKey)
				}
				return fmt.Errorf("pack directory %q does not exist "+
					"(omit the argument to verify the pack embedded in this binary)", args[0])
			}
			dir := args[0]
			lock, err := pack.ReadLock(dir)
			if err != nil {
				return fmt.Errorf("read lock (run `momus pack lock %s` first): %w", dir, err)
			}
			trusted := trustedKey
			res, err := pack.Verify(dir, lock, trusted)
			if err != nil {
				return err
			}
			for _, p := range res.Changed {
				fmt.Fprintf(os.Stderr, "  CHANGED  %s\n", p)
			}
			for _, p := range res.Added {
				fmt.Fprintf(os.Stderr, "  ADDED    %s\n", p)
			}
			for _, p := range res.Removed {
				fmt.Fprintf(os.Stderr, "  REMOVED  %s\n", p)
			}
			if res.DigestMismatch {
				fmt.Fprintf(os.Stderr, "  the lock's own digest does not match its file list\n")
			}
			if res.SignatureChecked {
				if res.SignatureValid {
					fmt.Fprintf(os.Stderr, "  signature: valid (%s)\n", shortKey(res.SignerKey))
				} else {
					fmt.Fprintf(os.Stderr, "  signature: INVALID\n")
				}
			} else if trusted != "" {
				return fmt.Errorf("a public key was pinned but the lock is not signed")
			}
			if !res.OK {
				return fmt.Errorf("pack verification FAILED")
			}
			signNote := ""
			if res.SignatureChecked && res.SignatureValid {
				signNote = " and signature verified"
			}
			fmt.Fprintf(os.Stderr, "OK: %d files match the lock%s\n", len(lock.Files), signNote)
			return nil
		},
	}
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "trusted Ed25519 public key (base64, or @file) to authenticate the signature")
	return cmd
}

func newPackSignCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "sign <pack-dir>",
		Short: "Sign a pack's lock digest with an Ed25519 private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if keyPath == "" {
				return fmt.Errorf("--key <private-key-file> is required")
			}
			keyB, err := os.ReadFile(keyPath)
			if err != nil {
				return err
			}
			priv, err := pack.PrivateKeyFromBase64(string(keyB))
			if err != nil {
				return err
			}
			// Always sign a freshly computed lock so the signature matches the
			// current pack content.
			lock, err := pack.Compute(dir)
			if err != nil {
				return err
			}
			if existing, err := pack.ReadLock(dir); err == nil {
				lock.Name, lock.Version = existing.Name, existing.Version
			}
			pack.Sign(lock, priv)
			if err := pack.WriteLock(dir, lock); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Signed %s\n  digest:     %s\n  public key: %s\n", dir, lock.Digest, lock.PublicKey)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "path to the Ed25519 private key file (base64)")
	return cmd
}

func newPackKeygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for signing packs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			privPath, pubPath := out+".key", out+".pub"
			// Never clobber an existing signing key: overwriting it would
			// permanently invalidate every pack already signed with it.
			if _, err := os.Stat(privPath); err == nil {
				return fmt.Errorf("%s already exists — refusing to overwrite a signing key "+
					"(use --out to pick another name, or delete it deliberately)", privPath)
			}
			priv, pub, err := pack.GenerateKey()
			if err != nil {
				return err
			}
			// O_EXCL closes the race between the check above and the write.
			f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if _, err := f.WriteString(priv + "\n"); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Wrote private key to %s (keep it secret) and public key to %s\n", privPath, pubPath)
			fmt.Fprintf(os.Stderr, "Public key: %s\n", pub)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "momus", "output filename prefix (writes <prefix>.key and <prefix>.pub)")
	return cmd
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// verifyEmbeddedPack checks the core pack compiled into this binary against the
// lock that was embedded alongside it, so the integrity claim holds for every
// distribution channel — not just a git checkout.
func verifyEmbeddedPack(trustedPubKey string) error {
	lockBytes, err := momus.CorePack.ReadFile(momus.CorePackRoot + "/" + pack.LockFileName)
	if err != nil {
		return fmt.Errorf("this binary has no embedded pack lock: %w", err)
	}
	lock, err := pack.ParseLock(lockBytes)
	if err != nil {
		return err
	}
	// A pinned key must be enforced here too: silently skipping the signature
	// check when one was requested would fail open.
	if trustedPubKey != "" && lock.Signature == "" {
		return fmt.Errorf("a public key was pinned but the embedded pack lock is not signed")
	}
	res, err := pack.VerifyFS(momus.CorePack, momus.CorePackRoot, lock)
	if err != nil {
		return err
	}
	if lock.Signature != "" {
		ok, serr := pack.VerifySignature(lock, trustedPubKey)
		if serr != nil {
			return serr
		}
		if !ok {
			return fmt.Errorf("embedded pack signature is INVALID")
		}
		fmt.Fprintf(os.Stderr, "  signature: valid (%s)\n", shortKey(lock.PublicKey))
	}
	for _, p := range res.Changed {
		fmt.Fprintf(os.Stderr, "  CHANGED  %s\n", p)
	}
	for _, p := range res.Added {
		fmt.Fprintf(os.Stderr, "  ADDED    %s\n", p)
	}
	for _, p := range res.Removed {
		fmt.Fprintf(os.Stderr, "  REMOVED  %s\n", p)
	}
	if !res.OK {
		return fmt.Errorf("embedded pack verification FAILED")
	}
	fmt.Fprintf(os.Stderr, "OK: %d files match the lock embedded in this binary\n", len(lock.Files))
	return nil
}

// resolvePubKey returns a base64 public key from a literal value or an @file ref.
func resolvePubKey(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if strings.HasPrefix(v, "@") {
		b, err := os.ReadFile(v[1:])
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(v), nil
}

func shortKey(k string) string {
	if len(k) > 16 {
		return k[:16] + "…"
	}
	return k
}
