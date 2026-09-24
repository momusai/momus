package main

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/momusai/momus/internal/store"
)

func newDiffCmd() *cobra.Command {
	var (
		dbPath   string
		target   string
		base     string
		head     string
		failOnRe bool
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two recorded scans and report what changed",
		Long: "Compares two runs from an evidence database (by default the two most\n" +
			"recent for a target) and reports what moved.\n\n" +
			"Momus scores with three-valued logic, and the third value matters here:\n" +
			"an attack that went from vulnerable to INCONCLUSIVE is not fixed, it is\n" +
			"undecided, and it is reported separately as lost signal. An attack that\n" +
			"simply did not run again is not a pass either.",
		Example: "  momus diff --store momus.db --target http://localhost:8000/chat\n" +
			"  momus diff --store momus.db --base 1a2b3c4d --head 5e6f7a8b\n" +
			"  momus diff --store momus.db --fail-on-regression   # exit 2 in CI",
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if (base == "") != (head == "") {
				return fmt.Errorf("--base and --head must be given together (or neither, to compare the two most recent runs)")
			}
			if base == "" && target == "" {
				return fmt.Errorf("specify --target to compare its two most recent runs, or --base and --head to compare specific runs")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open("", dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			var d *store.Diff
			if base != "" {
				d, err = s.DiffRuns(base, head)
			} else {
				d, err = s.DiffLatest(target)
			}
			if err != nil {
				return err
			}

			printDiff(os.Stdout, d)
			if failOnRe && d.HasRegressions() {
				return fmt.Errorf("%d regression(s) since the baseline run: %w",
					len(d.Regressions), errGateTripped)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "store", "momus.db", "path to the SQLite evidence database")
	cmd.Flags().StringVar(&target, "target", "", "compare the two most recent runs for this target URL")
	cmd.Flags().StringVar(&base, "base", "", "baseline run id (see `momus history`)")
	cmd.Flags().StringVar(&head, "head", "", "newer run id to compare against the baseline")
	cmd.Flags().BoolVar(&failOnRe, "fail-on-regression", false, "exit 2 if any attack newly succeeds against the target")
	return cmd
}

// printDiff renders the comparison. It takes an io.Writer so the wording of the
// "not fixed" distinctions can be asserted in tests.
func printDiff(out io.Writer, d *store.Diff) {
	fmt.Fprintf(out, "Comparing %s (%s) -> %s (%s)\n",
		d.Base.UID, d.Base.StartedAt, d.Head.UID, d.Head.StartedAt)
	if d.Base.Target != d.Head.Target {
		fmt.Fprintf(out, "Targets: %s -> %s\n\n", d.Base.Target, d.Head.Target)
	} else {
		fmt.Fprintf(out, "Target: %s\n\n", d.Head.Target)
	}

	red := color.New(color.FgRed, color.Bold).FprintfFunc()
	green := color.New(color.FgGreen).FprintfFunc()
	yellow := color.New(color.FgYellow).FprintfFunc()

	plain := func(w io.Writer, f string, a ...any) { fmt.Fprintf(w, f, a...) }

	section := func(label string, changes []store.Change, pf func(w io.Writer, f string, a ...any)) {
		if len(changes) == 0 {
			return
		}
		pf(out, "%s (%d)\n", label, len(changes))
		for _, c := range changes {
			arrow := string(c.From) + " -> " + string(c.To)
			if c.To == "" {
				arrow = string(c.From) + " -> (not run)"
			}
			if c.From == "" {
				arrow = "(no baseline) -> " + string(c.To)
			}
			fmt.Fprintf(out, "  %-9s %-34s %s\n", c.Severity, c.AttackID, arrow)
			if c.Reason != "" {
				fmt.Fprintf(out, "            %s\n", c.Reason)
			}
		}
		fmt.Fprintln(out)
	}

	section("REGRESSIONS — newly succeeding attacks", d.Regressions, red)
	section("FIXED — was vulnerable, now provably safe", d.Fixed, green)
	// Deliberately yellow, not green: a verdict we can no longer make is a gap in
	// coverage. The most dangerous row in this whole command is a
	// vulnerable -> inconclusive that someone reads as good news.
	section("LOST SIGNAL — no longer decidable, NOT fixed", d.LostSignal, yellow)
	section("NOT RUN — absent from the newer scan, state unknown", d.NotRun, yellow)
	section("NEWLY COVERED — no baseline to compare", d.NewlyCovered, plain)
	section("GAINED SIGNAL — newly decidable, no security change", d.GainedSignal, green)

	fmt.Fprintf(out, "Summary: %d regression(s), %d fixed, %d lost signal, %d unchanged\n",
		len(d.Regressions), len(d.Fixed), len(d.LostSignal), d.Unchanged)

	for _, n := range d.Notes {
		yellow(out, "NOTE: %s\n", n)
	}
}
