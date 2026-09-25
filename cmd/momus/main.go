// Command momus is the Momus CLI.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	momus "github.com/momusai/momus"
	"github.com/momusai/momus/internal/buildinfo"
	"github.com/momusai/momus/internal/judge"
	"github.com/momusai/momus/internal/mal"
	"github.com/momusai/momus/internal/report"
	"github.com/momusai/momus/internal/scanner"
	"github.com/momusai/momus/internal/store"
	"github.com/momusai/momus/internal/target"

	// The SQLite driver is registered here and nowhere else: internal/store
	// talks to database/sql only, so this single import is what binds it to a
	// concrete engine. modernc.org/sqlite is pure Go, which keeps the release
	// builds CGO_ENABLED=0 across all six platforms.
	_ "modernc.org/sqlite"
)

// version is stamped by the build (-ldflags "-X main.version=...").
var version = "dev"

// Hand the stamped version to the packages that send it as a User-Agent but
// cannot import main. One linker flag, one source of truth.
func init() { buildinfo.Version = version }

func main() {
	// Cancel in-flight work on Ctrl-C / SIGTERM so a long scan stops gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := &cobra.Command{
		Use:           "momus",
		Short:         "The harshest critic your AI will ever face.",
		Long:          banner(),
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.AddCommand(newScanCmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newInitCmd())
	root.AddCommand(newPackCmd())
	root.AddCommand(newHistoryCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newMCPCmd())

	if err := root.ExecuteContext(ctx); err != nil {
		// Exit 2 when the run succeeded but the --fail-on gate tripped on
		// findings; exit 1 for operational failures. Lets CI tell them apart.
		if errors.Is(err, errGateTripped) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func banner() string {
	return "" +
		"Momus — an open, modular framework for testing and defending\n" +
		"the security of AI models, agents, and MCP servers.\n" +
		"\n" +
		"  docs:    https://momus.dev\n" +
		"  source:  https://github.com/momusai/momus"
}

// ---- momus scan --------------------------------------------------------

type scanOpts struct {
	pack          string
	json          bool
	html          string
	sarif         string
	failOn        string
	concurrency   int
	limit         int
	category      string
	dryRun        bool
	skipProbe     bool
	judgeURL      string
	judgeModel    string
	judgeProvider string
	judgeThresh   float64
	store         string
}

func newScanCmd() *cobra.Command {
	opts := &scanOpts{}
	cmd := &cobra.Command{
		Use:   "scan <target-url>",
		Short: "Scan an AI endpoint with an attack pack",
		Example: "  momus scan http://localhost:8000\n" +
			"  momus scan https://api.openai.com/v1/chat/completions --fail-on high\n" +
			"  momus scan https://api.anthropic.com/v1/messages --sarif momus.sarif",
		Args: func(cmd *cobra.Command, args []string) error {
			switch {
			case len(args) == 0:
				return fmt.Errorf("missing <target-url> — the AI endpoint to scan\n\nexamples:\n%s", cmd.Example)
			case len(args) > 1:
				return fmt.Errorf("expected one <target-url>, got %d arguments", len(args))
			}
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.validate()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), args[0], opts)
		},
	}
	opts.addFlags(cmd)
	return cmd
}

// validate checks the scan flags before anything is sent. It is shared with
// `momus mcp scan`, which takes the same options against a different transport;
// duplicating it would let the two drift, and a gate that silently fails open
// in one of them is exactly the kind of difference nobody notices.
func (opts *scanOpts) validate() error {
	{
		// Validate --fail-on up front: an unrecognized value must be an error,
		// not silently disable the gate (which would fail open in CI).
		switch opts.failOn {
		case "", "any", "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid --fail-on %q (want any|info|low|medium|high|critical)", opts.failOn)
		}
		opts.judgeProvider = strings.ToLower(strings.TrimSpace(opts.judgeProvider))
		switch opts.judgeProvider {
		case "", "openai", "anthropic", "fake":
		default:
			return fmt.Errorf("invalid --judge-provider %q (want openai|anthropic)", opts.judgeProvider)
		}
		if opts.concurrency < 1 {
			return fmt.Errorf("--concurrency must be at least 1, got %d", opts.concurrency)
		}
		// A negative --limit was silently ignored (selectAttacks only
		// narrows when limit > 0), so `--limit -1` dispatched the whole
		// pack at a target the user meant to sample.
		if opts.limit < 0 {
			return fmt.Errorf("--limit must be 0 (the whole pack) or a positive number, got %d", opts.limit)
		}
		// Check report destinations BEFORE scanning: discovering an unwritable
		// path after a long (and possibly paid) scan wastes the whole run. The
		// evidence database is checked here too — runScan opens it before
		// dispatching attacks, but that is still after the liveness probe has
		// spent two real calls on the target.
		for _, p := range []string{opts.html, opts.sarif, opts.store} {
			if err := checkWritable(p); err != nil {
				return err
			}
		}
		return nil
	}
}

// addFlags registers the scan options on a command.
func (opts *scanOpts) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&opts.pack, "pack", "packs/core", "path to an attack pack directory")
	cmd.Flags().BoolVar(&opts.json, "json", false, "emit findings as JSON to stdout")
	cmd.Flags().StringVar(&opts.html, "html", "", "write a self-contained HTML report to this path")
	cmd.Flags().StringVar(&opts.sarif, "sarif", "", "write a SARIF 2.1.0 report to this path (for GitHub code scanning)")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "", "exit 2 if a vulnerable finding meets this severity floor: any|info|low|medium|high|critical")
	cmd.Flags().IntVar(&opts.concurrency, "concurrency", 8, "number of attacks to run in flight at once")
	cmd.Flags().IntVar(&opts.limit, "limit", 0, "run at most N attacks (0 = the whole pack); useful against paid endpoints")
	cmd.Flags().StringVar(&opts.category, "category", "", "only run attacks in this category (e.g. prompt-injection)")
	cmd.Flags().BoolVar(&opts.skipProbe, "skip-probe", false, "skip the liveness probe that checks the target behaves like a model")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print what would be sent (attack and judge call counts) without calling the target")
	cmd.Flags().StringVar(&opts.judgeURL, "judge-url", "", "judge endpoint (else MOMUS_JUDGE_URL); enables llm_judge scoring")
	cmd.Flags().StringVar(&opts.judgeModel, "judge-model", "", "judge model (else MOMUS_JUDGE_MODEL)")
	cmd.Flags().StringVar(&opts.judgeProvider, "judge-provider", "", "judge provider: openai|anthropic (else auto)")
	cmd.Flags().Float64Var(&opts.judgeThresh, "judge-threshold", 0, "min judge confidence 0..1 (else MOMUS_JUDGE_THRESHOLD, default 0.7)")
	cmd.Flags().StringVar(&opts.store, "store", "", "record the run in this SQLite evidence file, for `momus history` and `momus diff`")
}

func runScan(ctx context.Context, url string, opts *scanOpts) error {
	tgt, err := target.Build(url)
	if err != nil {
		return err
	}
	return runScanWith(ctx, tgt, url, opts)
}

// runScanWith drives a scan against an already-built target. `scan` resolves
// one from a URL; `mcp scan` builds one by connecting to an MCP server and
// choosing a tool.
func runScanWith(ctx context.Context, tgt target.Target, url string, opts *scanOpts) error {
	if ctx == nil {
		ctx = context.Background()
	}
	attacks, packLabel, skipped, err := loadAttacks(opts.pack)
	if err != nil {
		return err
	}
	if len(attacks) == 0 {
		return fmt.Errorf("no attacks loaded from %s", packLabel)
	}
	// A pack that only half-parsed must not scan the survivors and report a
	// clean gate pass: the attacks that failed to load are exactly the ones
	// nobody tested, and a WARN log line is invisible in CI. Refuse up front,
	// before a single request is sent.
	if len(skipped) > 0 {
		for _, sk := range skipped {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", sk.Path, sk.Err)
		}
		return fmt.Errorf("%d of %d attack files in %s failed to parse; refusing to scan a partial "+
			"pack (run `momus validate %s` to see why, or fix the files listed above)",
			len(skipped), len(attacks)+len(skipped), packLabel, opts.pack)
	}
	attacks, err = selectAttacks(attacks, opts.category, opts.limit)
	if err != nil {
		return err
	}

	jcfg := judge.ConfigFromEnv()
	if opts.judgeURL != "" {
		jcfg.BaseURL = opts.judgeURL
	}
	if opts.judgeModel != "" {
		jcfg.Model = opts.judgeModel
	}
	if opts.judgeProvider != "" {
		jcfg.Provider = opts.judgeProvider
	}
	if opts.judgeThresh > 0 {
		jcfg.Threshold = opts.judgeThresh
	}
	jcfg.TargetURL = url
	// So one endpoint serving several models is not mistaken for the model
	// grading itself — the usual shape for a local Ollama or vLLM.
	jcfg.TargetModel = os.Getenv("MOMUS_MODEL")
	j, err := judge.New(jcfg)
	if err != nil {
		return err
	}

	if opts.dryRun {
		return printDryRun(attacks, packLabel, url, tgt.Name(), j.Name())
	}

	fmt.Fprintf(os.Stderr, "Loaded %d attacks from %s\n", len(attacks), packLabel)
	fmt.Fprintf(os.Stderr, "Target adapter: %s\n", tgt.Name())
	fmt.Fprintf(os.Stderr, "Judge: %s\n", j.Name())
	fmt.Fprintf(os.Stderr, "Scanning %s\n\n", url)

	if !opts.skipProbe {
		if err := probeLive(ctx, tgt); err != nil {
			return err
		}
	}

	// Open the evidence database BEFORE scanning. Ping()-ing it here turns a bad
	// path or an unreadable schema into an immediate error instead of one raised
	// after a scan that already spent minutes and real API credit.
	var st *store.Store
	if opts.store != "" {
		st, err = store.Open("", opts.store)
		if err != nil {
			return err
		}
		defer st.Close()
	}

	startedAt := time.Now()
	sc := scanner.New(tgt,
		scanner.WithJudge(j),
		scanner.WithConcurrency(opts.concurrency),
		scanner.WithProgress(progressReporter(len(attacks))),
	)
	findings := sc.Run(ctx, attacks)
	finishedAt := time.Now()

	clearProgress()

	// Emit findings FIRST so a later report-write failure never discards the
	// scan's results.
	if opts.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			return err
		}
	} else {
		renderTerminal(findings)
	}

	// Diagnostics go to stderr so they never corrupt the JSON on stdout — and
	// they are printed in BOTH modes. --json is the mode CI runs, where nobody
	// reads scrollback, so it is the mode that most needs to be told that the
	// scan was partial or that the target never behaved like a model. Putting
	// these only in the terminal branch meant the machine-readable output came
	// back as a clean list of "safe" verdicts with no caveat anywhere.
	if opts.limit > 0 || opts.category != "" {
		fmt.Fprintf(os.Stderr,
			"\nNOTE: this was a PARTIAL scan (%d of the pack's attacks%s). "+
				"A clean result here does not cover the rest of the pack.\n",
			len(attacks), categoryNote(opts.category))
	}
	warnStaticTarget(findings)
	judgeDiagnostics(findings, j)

	// Detect an interrupted scan BEFORE the reports are written. The exit code
	// alone is not enough: a SARIF uploaded to code scanning, or an HTML report
	// forwarded to someone, outlives this process and must say on its face that
	// most of the pack never ran.
	interrupted := ctx.Err() != nil || len(findings) < len(attacks)

	rmeta := report.Meta{
		Target:      url,
		Pack:        packLabel,
		JudgeName:   j.Name(),
		Version:     version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	rmeta.PartialScope = scanScope(interrupted, len(findings), len(attacks), opts.limit, opts.category)
	if opts.html != "" {
		if err := report.WriteHTMLFile(opts.html, rmeta, findings); err != nil {
			return fmt.Errorf("write html report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "HTML report written to %s\n", opts.html)
	}
	if opts.sarif != "" {
		if err := report.WriteSARIFFile(opts.sarif, rmeta, findings); err != nil {
			return fmt.Errorf("write sarif report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "SARIF report written to %s\n", opts.sarif)
	}
	// Record the run BEFORE the interrupted/inconclusive guards below return an
	// error. A partial run is still evidence worth keeping, and PartialScope
	// carries the caveat into the database so `momus diff` cannot later mistake
	// it for a full pass. A failed write is an operational error, not a warning:
	// the user asked for a durable record and did not get one.
	if st != nil {
		uid, serr := st.SaveRun(store.Run{
			StartedAt:    startedAt,
			FinishedAt:   finishedAt,
			Target:       url,
			Pack:         packLabel,
			Version:      version,
			JudgeName:    j.Name(),
			PartialScope: rmeta.PartialScope,
		}, findings)
		if serr != nil {
			return serr
		}
		fmt.Fprintf(os.Stderr, "run %s recorded in %s\n", uid, opts.store)
	}

	// An interrupted scan (Ctrl-C / SIGTERM) must NOT be mistaken for a clean
	// gate pass: it ran only part of the pack, so the un-run attacks — possibly
	// the vulnerable ones — were never tested. Reports are already written above
	// (marked INTERRUPTED) for diagnostics; return an operational error (exit 1)
	// rather than exit 0.
	if interrupted {
		return fmt.Errorf("scan interrupted: only %d of %d attacks completed", len(findings), len(attacks))
	}

	// A scan that produced NO decisive verdict tested nothing — a wrong model
	// name, an expired key, or sustained throttling makes every attack
	// inconclusive. Exiting 0 there would show CI a green check for an untested
	// target, so it is an operational failure (exit 1), not a clean pass.
	decisive := 0
	for _, f := range findings {
		if f.Verdict != scanner.VerdictInconclusive {
			decisive++
		}
	}
	if len(findings) > 0 && decisive == 0 {
		return fmt.Errorf("scan produced no usable results: all %d attacks were inconclusive "+
			"(check the target URL, model, and credentials — see the reasons above)", len(findings))
	}

	// A judge that was configured but failed on EVERY call means the semantic half
	// of the pack was never evaluated. The deterministic attacks still produced
	// verdicts, so the guard above doesn't fire — but reporting "0 vulnerable" and
	// exiting 0 would hide a total loss of semantic coverage. Treat it as an
	// operational failure so CI can't read it as a clean pass.
	if j != nil && j.Name() != "none" {
		attempted, failed := judgeCallStats(findings)
		if attempted > 0 && failed == attempted {
			return fmt.Errorf("the judge failed on all %d call(s): semantic checks were not evaluated "+
				"(see the warning above); fix the judge configuration or run without one", failed)
		}
	}

	if n := failCount(findings, opts.failOn); n > 0 {
		return fmt.Errorf("%d vulnerable finding(s) at or above severity %q: %w", n, opts.failOn, errGateTripped)
	}
	return nil
}

// errGateTripped marks a non-zero exit caused by --fail-on findings (exit 2),
// distinct from an operational failure (exit 1).
var errGateTripped = errors.New("scan gate tripped by findings")

// selectAttacks narrows the pack so a run against a paid endpoint can be scoped
// (by category, or to the first N attacks) instead of always spending 200 calls.
func selectAttacks(attacks []mal.Attack, category string, limit int) ([]mal.Attack, error) {
	if category != "" {
		var kept []mal.Attack
		seen := map[string]bool{}
		for _, a := range attacks {
			seen[a.Category] = true
			if a.Category == category {
				kept = append(kept, a)
			}
		}
		if len(kept) == 0 {
			var names []string
			for c := range seen {
				names = append(names, c)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("no attacks in category %q; available: %s",
				category, strings.Join(names, ", "))
		}
		attacks = kept
	}
	if limit > 0 && limit < len(attacks) {
		attacks = attacks[:limit]
	}
	return attacks, nil
}

// printDryRun shows what a scan would cost before any call is made.
func printDryRun(attacks []mal.Attack, packLabel, url, adapter, judgeName string) error {
	judged := 0
	byCategory := map[string]int{}
	for i := range attacks {
		byCategory[attacks[i].Category]++
		if attacks[i].Detect.UsesJudge() {
			judged++
		}
	}
	fmt.Printf("Dry run — nothing was sent.\n\n")
	fmt.Printf("  pack:            %s\n", packLabel)
	fmt.Printf("  target:          %s (%s adapter)\n", url, adapter)
	fmt.Printf("  judge:           %s\n", judgeName)
	fmt.Printf("  target calls:    %d (one per attack)\n", len(attacks))
	if judgeName == "none" {
		fmt.Printf("  judge calls:     0 — %d attack(s) would be inconclusive without a judge\n", judged)
	} else {
		fmt.Printf("  judge calls:     up to %d (only when the cheap checks are undecided)\n", judged)
	}
	fmt.Printf("\n  attacks by category:\n")
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Printf("    %-28s %d\n", c, byCategory[c])
	}
	return nil
}

// probeLive checks the target actually behaves like a language model before we
// spend a whole pack on it. Two different benign prompts are sent: a real model
// echoes the fresh nonce or at least answers them differently, while a health
// endpoint, static page, or gateway that swallows the body returns the same thing
// both times. Without this, `momus scan https://api.example.com/health` reports a
// perfect 200/200 "safe" — a clean bill of health for a target with no model
// behind it at all.
func probeLive(ctx context.Context, tgt target.Target) error {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil // can't probe; don't block the scan
	}
	token := "MOMUS_LIVE_" + strings.ToUpper(hex.EncodeToString(nonce[:]))

	first, err := tgt.Send(ctx, target.Request{
		Payload: "Reply with exactly this token and nothing else: " + token,
	})
	if err != nil {
		return fmt.Errorf("the target did not answer a benign probe: %w", err)
	}
	if strings.Contains(first.Text, token) {
		return nil // echoed the nonce: definitely processing prompts
	}
	second, err := tgt.Send(ctx, target.Request{
		Payload: "In one short sentence, what is the capital city of France?",
	})
	if err != nil {
		return fmt.Errorf("the target did not answer a benign probe: %w", err)
	}
	if strings.TrimSpace(first.Text) == strings.TrimSpace(second.Text) {
		return fmt.Errorf("the target returned the SAME reply to two different benign prompts, "+
			"so it does not appear to process prompts at all (is this URL a health check, a static "+
			"page, or a gateway?). Scanning it would report every attack \"safe\" without testing "+
			"anything. Re-run with --skip-probe to override.\n  reply was: %s",
			snippetOf(first.Text))
	}
	return nil
}

func snippetOf(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// clearProgress erases the in-place progress line before results are printed.
// It runs unconditionally: an interrupted scan never reaches done==total, so
// relying on the last callback to clean up would leave a stale line behind.
func clearProgress() {
	if info, err := os.Stderr.Stat(); err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

// progressReporter returns a progress callback that redraws a counter on a
// terminal. A scan takes minutes against a real endpoint, and printing nothing
// is indistinguishable from a hang. It stays silent when stderr is redirected
// (CI logs, pipes) so it can't spam a log file with carriage returns.
func progressReporter(total int) func(done, total int) {
	info, err := os.Stderr.Stat()
	isTTY := err == nil && (info.Mode()&os.ModeCharDevice) != 0
	if !isTTY || total == 0 {
		return nil
	}
	var mu sync.Mutex
	shown := 0
	return func(done, total int) {
		mu.Lock()
		defer mu.Unlock()
		if done <= shown {
			return // an out-of-order callback must not redraw a stale count
		}
		shown = done
		fmt.Fprintf(os.Stderr, "\r  scanning %d/%d attacks…", done, total)
	}
}

// checkWritable verifies a report destination can actually be written, so a scan
// isn't wasted discovering it afterwards. An empty path means "not requested".
func checkWritable(path string) error {
	if path == "" {
		return nil
	}
	// A path that is itself a directory can never be written as a report. Catch
	// it here and say so, rather than reporting on its parent — `--sarif /tmp`
	// used to fail with "cannot write to /", which names the wrong thing.
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("cannot write %s: it is a directory, not a file "+
			"(give a filename, e.g. %s)", path, filepath.Join(path, "momus.sarif"))
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot write %s: directory %s does not exist", path, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("cannot write %s: %s is not a directory", path, dir)
	}
	// Probe with a temp file in the same directory (what the atomic writer does).
	f, err := os.CreateTemp(dir, ".momus-writecheck-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %s is not writable: %w", path, dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// defaultPackDir is the flag default for --pack.
const defaultPackDir = "packs/core"

// loadAttacks loads the pack from disk, falling back to the core pack embedded
// in the binary when the default pack dir is absent (e.g. an installed binary
// run outside the repo, or via npx). Returns the attacks and a display label.
func loadAttacks(packDir string) ([]mal.Attack, string, []mal.Skipped, error) {
	// `--pack embedded` forces the pack built into the binary.
	if packDir == "embedded" {
		a, sk, err := mal.LoadPackFSDetailed(momus.CorePack, momus.CorePackRoot)
		return a, "embedded core pack", sk, err
	}
	// Any other explicit --pack is taken at face value: if the user named it, a
	// failure to load it is an error, not something to paper over.
	if packDir != defaultPackDir {
		a, sk, err := mal.LoadPackDetailed(packDir)
		return a, packDir, sk, err
	}

	// For the DEFAULT path, only prefer an on-disk packs/core when it is a
	// directory that actually yields attacks. Otherwise an unrelated file or
	// empty folder named "packs/core" in the working directory would silently
	// shadow (or hard-fail) the pack built into the binary.
	loadEmbedded := func() ([]mal.Attack, string, []mal.Skipped, error) {
		a, sk, err := mal.LoadPackFSDetailed(momus.CorePack, momus.CorePackRoot)
		return a, "embedded core pack", sk, err
	}
	info, statErr := os.Stat(packDir)
	if statErr != nil || !info.IsDir() {
		return loadEmbedded()
	}
	a, sk, err := mal.LoadPackDetailed(packDir)
	if err != nil || len(a) == 0 {
		fmt.Fprintf(os.Stderr, "note: ignoring %s (%s); using the pack embedded in this binary\n",
			packDir, packLoadProblem(err))
		return loadEmbedded()
	}
	return a, packDir, sk, nil
}

func packLoadProblem(err error) string {
	if err != nil {
		return err.Error()
	}
	return "it contains no attacks"
}

// severityFloor maps a severity name to a rank; higher is more severe.
var severityFloor = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// failCount returns how many vulnerable findings meet the --fail-on threshold.
// failOn is "" (never fail), "any" (any vulnerable), or a severity floor.
func failCount(findings []scanner.Finding, failOn string) int {
	if failOn == "" {
		return 0
	}
	floor := -1 // "any"
	if failOn != "any" {
		r, ok := severityFloor[failOn]
		if !ok {
			return 0 // unknown threshold: do not gate (validated earlier in PreRunE)
		}
		floor = r
	}
	n := 0
	for _, f := range findings {
		if f.Verdict != scanner.VerdictVulnerable {
			continue
		}
		rank, ok := severityFloor[string(f.Severity)]
		if !ok {
			// Unknown severity should never silently pass the gate; treat it as
			// most-severe so the gate trips (fail-safe). Attack.Validate rejects
			// unknown severities at load time, so this is defense-in-depth.
			rank = len(severityFloor)
		}
		if rank >= floor {
			n++
		}
	}
	return n
}

func renderTerminal(findings []scanner.Finding) {
	bold := color.New(color.Bold).SprintFunc()
	vuln, safe, inc := 0, 0, 0
	for _, f := range findings {
		switch f.Verdict {
		case scanner.VerdictVulnerable:
			vuln++
			fmt.Fprintf(color.Output, "  %s  %s  %s\n",
				color.New(color.BgRed, color.FgWhite, color.Bold).Sprint(" VULN "),
				bold(f.AttackID), f.AttackName)
		case scanner.VerdictSafe:
			safe++
			fmt.Fprintf(color.Output, "  %s  %s  %s\n",
				color.New(color.FgGreen).Sprint(" safe "),
				f.AttackID, f.AttackName)
		case scanner.VerdictInconclusive:
			inc++
			fmt.Fprintf(color.Output, "  %s  %s  %s  (%s)\n",
				color.New(color.FgYellow).Sprint(" ???  "),
				f.AttackID, f.AttackName, f.Reason)
		}
	}
	fmt.Fprintln(color.Output)
	fmt.Fprintf(color.Output, "%s: %s vulnerable, %s safe, %s inconclusive\n",
		bold("Summary"),
		color.RedString("%d", vuln),
		color.GreenString("%d", safe),
		color.YellowString("%d", inc))
}

// judgeDiagnostics explains an "inconclusive" count so a user can tell apart the
// three very different causes: no judge configured, a BROKEN judge (bad key,
// wrong model, throttled), and a judge that genuinely couldn't decide. Without
// this, a 401 from the judge looks exactly like having no judge at all.
func judgeDiagnostics(findings []scanner.Finding, j judge.Judge) {
	inc := 0
	for _, f := range findings {
		if f.Verdict == scanner.VerdictInconclusive {
			inc++
		}
	}
	if inc == 0 {
		return
	}

	// Count judge calls that failed outright (transport/status), and keep one
	// example to show the operator.
	failed, sample := 0, ""
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.Decision == judge.DecisionInconclusive && judgeCallFailed(e.Rationale) {
				failed++
				if sample == "" {
					sample = e.Rationale
				}
			}
		}
	}

	switch {
	case failed > 0:
		fmt.Fprintf(os.Stderr,
			"\nWARNING: the judge failed on %d call(s), so semantic checks were NOT evaluated.\n"+
				"  first error: %s\n"+
				"  Check MOMUS_JUDGE_URL / MOMUS_JUDGE_MODEL / MOMUS_JUDGE_API_KEY.\n", failed, sample)
	case j == nil || j.Name() == "none":
		fmt.Fprintf(os.Stderr,
			"\n%d attack(s) need a judge to decide (semantic checks stay inconclusive rather than\n"+
				"risk a false positive). Configure one — it can be local and free:\n"+
				"  export MOMUS_JUDGE_URL=http://localhost:11434/v1/chat/completions\n"+
				"  export MOMUS_JUDGE_MODEL=llama3.1\n", inc)
	default:
		fmt.Fprintf(os.Stderr,
			"\n%d attack(s) were inconclusive: the judge answered but was not confident enough\n"+
				"to call them either way. Review them manually, or lower --judge-threshold.\n", inc)
	}
}

// scanScope describes how much of the pack a run actually covered, for the
// header of the HTML report and the SARIF run properties. An empty string means
// a complete run. An interrupted scan takes precedence over --limit/--category:
// it is the more serious caveat, and the two can happen together.
func scanScope(interrupted bool, ran, planned, limit int, category string) string {
	switch {
	case interrupted:
		return fmt.Sprintf("INTERRUPTED: only %d of %d attacks ran; the rest were never tested", ran, planned)
	case limit > 0 || category != "":
		return fmt.Sprintf("PARTIAL: %d of the pack's attacks%s", planned, categoryNote(category))
	default:
		return ""
	}
}

func categoryNote(category string) string {
	if category == "" {
		return ""
	}
	return ", category " + category
}

// warnStaticTarget flags an endpoint that returned the SAME reply to every attack.
// A real model varies its answers; an identical reply every time usually means the
// URL is a health check, a static page, or a stub — in which case "all safe" says
// nothing about a model.
func warnStaticTarget(findings []scanner.Finding) {
	first, n, identical := "", 0, true
	for _, f := range findings {
		if f.Response == nil {
			continue
		}
		if n == 0 {
			first = f.Response.Text
		} else if f.Response.Text != first {
			identical = false
			break
		}
		n++
	}
	if identical && n > 3 {
		fmt.Fprintf(os.Stderr,
			"\nWARNING: all %d responses were byte-identical. That is unusual for a model —\n"+
				"check the URL actually points at a chat/completion endpoint rather than a\n"+
				"health check or static page, or these results say nothing about a model.\n", n)
	}
}

// judgeCallStats counts judge invocations and how many of those failed outright.
func judgeCallStats(findings []scanner.Finding) (attempted, failed int) {
	for _, f := range findings {
		for _, e := range f.Evidence {
			attempted++
			if e.Decision == judge.DecisionInconclusive && judgeCallFailed(e.Rationale) {
				failed++
			}
		}
	}
	return attempted, failed
}

// judgeCallFailed reports whether a judge rationale describes a failed CALL (as
// opposed to a judge that answered but was unsure). The prefixes are the ones the
// judge package emits for transport/HTTP/parse problems; they are matched with a
// prefix check so model-authored rationale text can't be mistaken for a failure.
func judgeCallFailed(rationale string) bool {
	for _, p := range []string{"transport:", "status ", "unparseable", "build request:", "nonce mismatch"} {
		if strings.HasPrefix(rationale, p) {
			return true
		}
	}
	return false
}

// ---- momus validate ----------------------------------------------------

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <pack-dir>",
		Short: "Validate every MAL attack in a pack directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := mal.ValidatePack(args[0])
			if err != nil {
				return err
			}
			bad := 0
			for _, r := range results {
				if r.Err != nil {
					bad++
					fmt.Fprintf(color.Output, "  %s  %s  %s\n", color.RedString("FAIL"), r.Path, r.Err)
				} else {
					fmt.Fprintf(color.Output, "  %s  %s\n", color.GreenString("ok  "), r.ID)
				}
			}
			fmt.Printf("\n%d attacks, %d invalid, in %s\n", len(results), bad, args[0])
			if len(results) == 0 {
				return fmt.Errorf("no attack files found in %s", args[0])
			}
			if bad > 0 {
				return fmt.Errorf("%d invalid attack(s)", bad)
			}
			return nil
		},
	}
}
