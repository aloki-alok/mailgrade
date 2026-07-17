// Package report renders a checks.Report for humans (a graded summary with a
// status line per check) or for machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aloki-alok/mailgrade/internal/checks"
	"github.com/aloki-alok/mailgrade/internal/ui"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r checks.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonView(r))
}

// Terminal writes the human report: the domain and grade, a line per check, and
// the fixes for anything that did not pass.
func Terminal(w io.Writer, r checks.Report, st ui.Style, verbose bool) {
	fmt.Fprintf(w, "\n  %s   %s   %s\n",
		st.Bold(r.Domain),
		gradeBadge(r.Grade, st),
		st.Bold(fmt.Sprintf("%d/100", r.Score)))
	fmt.Fprintf(w, "  %s\n\n", st.Dim(r.Verdict()))

	for _, res := range r.Results {
		fmt.Fprintf(w, "  %s  %-12s %s\n", mark(res.Status, st), res.Name, st.Dim(res.Summary))
		if verbose {
			for _, f := range res.Findings {
				fmt.Fprintf(w, "        %s\n", st.Dim(f))
			}
		}
	}

	fmt.Fprintln(w)
	printFixes(w, r, st)
}

// printFixes lists the actionable fixes for every non-passing check.
func printFixes(w io.Writer, r checks.Report, st ui.Style) {
	printed := false
	for _, res := range r.Results {
		if res.Status == checks.Pass || res.Status == checks.NA || res.Status == checks.Skip {
			continue
		}
		if len(res.Fixes) == 0 {
			continue
		}
		if !printed {
			fmt.Fprintf(w, "  %s\n", st.Bold("Fixes"))
			printed = true
		}
		for _, fix := range res.Fixes {
			fmt.Fprintf(w, "    %s %s %s\n", mark(res.Status, st), st.Dim(res.Name+":"), fix)
		}
	}
	if printed {
		fmt.Fprintln(w)
	}
}

func mark(s checks.Status, st ui.Style) string {
	switch s {
	case checks.Pass:
		return st.Green("✓") // ✓
	case checks.Warn:
		return st.Yellow("⚠") // ⚠
	case checks.Fail:
		return st.Red("✗") // ✗
	case checks.NA:
		return st.Dim("─") // ─
	default: // Skip
		return st.Dim("·") // ·
	}
}

func gradeBadge(grade string, st ui.Style) string {
	badge := " " + grade + " "
	switch grade {
	case "A", "B":
		return st.Green(st.Bold(badge))
	case "C", "D":
		return st.Yellow(st.Bold(badge))
	default:
		return st.Red(st.Bold(badge))
	}
}
