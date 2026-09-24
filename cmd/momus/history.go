package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/momusai/momus/internal/store"
)

func newHistoryCmd() *cobra.Command {
	var (
		dbPath string
		target string
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List scan runs recorded in an evidence database",
		Long: "Lists the runs stored by `momus scan --store`, newest first.\n\n" +
			"Runs that covered only part of the pack are marked PARTIAL: a clean\n" +
			"summary on one of those says nothing about the attacks that never ran.",
		Example: "  momus history --store momus.db\n" +
			"  momus history --store momus.db --target http://localhost:8000/chat --limit 10",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open("", dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			runs, err := s.ListRuns(target, limit)
			if err != nil {
				return err
			}
			if len(runs) == 0 {
				fmt.Fprintf(os.Stderr, "no runs recorded in %s%s\n", dbPath, targetSuffix(target))
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "RUN\tSTARTED\tTARGET\tVULN\tSAFE\tINCONC\tSCOPE")
			for _, r := range runs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%s\n",
					r.UID, r.StartedAt, r.Target, r.Vulnerable, r.Safe, r.Inconclusive,
					scopeCell(r))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&dbPath, "store", "momus.db", "path to the SQLite evidence database")
	cmd.Flags().StringVar(&target, "target", "", "only list runs against this target URL")
	cmd.Flags().IntVar(&limit, "limit", 20, "show at most N runs (0 = all)")
	return cmd
}

// scopeCell keeps the PARTIAL marker short enough for a table while still
// naming it. The full scope string is in the database for anyone who needs it.
func scopeCell(r store.RunSummary) string {
	if !r.Partial() {
		return "full"
	}
	scope := r.PartialScope
	if i := strings.IndexByte(scope, ','); i > 0 {
		scope = scope[:i]
	}
	return scope
}

func targetSuffix(target string) string {
	if target == "" {
		return ""
	}
	return " for target " + target
}
