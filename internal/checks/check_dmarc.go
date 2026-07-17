package checks

import (
	"strings"

	"github.com/aloki-alok/mailgrade/internal/records"
)

// checkDMARC finds the _dmarc policy and grades its enforcement: reject and
// quarantine pass, none is monitor-only (warn), and a reduced pct or missing
// reporting address is noted.
func (s *Scanner) checkDMARC() Result {
	r := Result{Name: "DMARC"}
	txt, ok := s.firstTXT("_dmarc."+s.domain, func(t string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1")
	})
	if !ok {
		r.Status = Fail
		r.penalty = 20
		r.Summary = "no DMARC record"
		r.Fixes = []string{`Publish _dmarc TXT "v=DMARC1; p=none; rua=mailto:you@example.com" to start monitoring, then tighten to quarantine or reject.`}
		return r
	}

	d, _ := records.ParseDMARC(txt)
	r.Summary = "p=" + orNone(d.Policy)

	switch d.Policy {
	case "reject", "quarantine":
		r.Status = Pass
	case "none":
		r.Status = Warn
		r.penalty = 10
		r.Findings = append(r.Findings, "p=none only monitors; it does not protect against spoofing")
		r.Fixes = append(r.Fixes, "Once your reports look clean, move to p=quarantine and then p=reject.")
	default:
		r.Status = Warn
		r.penalty = 10
		r.Findings = append(r.Findings, "missing or unrecognized p= policy")
		r.Fixes = append(r.Fixes, "Set p=quarantine or p=reject.")
	}

	if d.RUA == "" {
		r.Status = worst(r.Status, Warn)
		r.penalty += 3
		r.Findings = append(r.Findings, "no rua= aggregate reporting address, so you get no visibility")
		r.Fixes = append(r.Fixes, "Add rua=mailto:<address> to receive aggregate reports.")
	}
	if pct := d.Pct; pct != "" && pct != "100" {
		r.Findings = append(r.Findings, "pct="+pct+": the policy applies to only some mail")
	}
	return r
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
