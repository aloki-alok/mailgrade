package report

import "github.com/aloki-alok/mailgrade/internal/checks"

// reportJSON is the machine-readable shape: statuses serialize as words rather
// than the internal enum's integer.
type reportJSON struct {
	Domain  string      `json:"domain"`
	Score   int         `json:"score"`
	Grade   string      `json:"grade"`
	Results []checkJSON `json:"results"`
}

type checkJSON struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Summary  string   `json:"summary"`
	Findings []string `json:"findings,omitempty"`
	Fixes    []string `json:"fixes,omitempty"`
}

func jsonView(r checks.Report) reportJSON {
	out := reportJSON{Domain: r.Domain, Score: r.Score, Grade: r.Grade}
	out.Results = make([]checkJSON, 0, len(r.Results))
	for _, res := range r.Results {
		out.Results = append(out.Results, checkJSON{
			Name:     res.Name,
			Status:   res.Status.String(),
			Summary:  res.Summary,
			Findings: res.Findings,
			Fixes:    res.Fixes,
		})
	}
	return out
}
