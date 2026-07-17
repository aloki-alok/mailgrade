package checks

import (
	"fmt"
	"strings"

	"github.com/aloki-alok/mailgrade/internal/records"
)

// checkSPF finds the domain's SPF record, checks its `all` qualifier, and counts
// the DNS lookups it incurs (resolving includes and redirects recursively)
// against the RFC 7208 limit of ten.
func (s *Scanner) checkSPF() Result {
	r := Result{Name: "SPF"}
	txt, ok := s.firstTXT(s.domain, func(t string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1")
	})
	if !ok {
		r.Status = Fail
		r.penalty = 20
		r.Summary = "no SPF record"
		r.Fixes = []string{`Publish a TXT record like "v=spf1 include:<your-provider> -all".`}
		return r
	}

	spf, _ := records.ParseSPF(txt)
	r.Summary = fmt.Sprintf("v=spf1 with %s", allDesc(spf.AllQualifier))

	lookups := s.countSPFLookups(txt, map[string]bool{}, 0)
	r.Findings = append(r.Findings, fmt.Sprintf("%d DNS-lookup mechanism(s) of the 10 allowed", lookups))

	switch spf.AllQualifier {
	case "+":
		r.Status = Fail
		r.penalty = 20
		r.Findings = append(r.Findings, "+all lets any server send as your domain")
		r.Fixes = []string{"Change +all to -all (or ~all) so only your listed senders pass."}
	case "":
		r.Status = Warn
		r.penalty = 8
		r.Findings = append(r.Findings, "no `all` mechanism: the record has no default policy")
		r.Fixes = []string{"End the record with -all (hard fail) or ~all (soft fail)."}
	case "?":
		r.Status = Warn
		r.penalty = 6
		r.Findings = append(r.Findings, "?all is neutral: receivers get no signal on unlisted senders")
		r.Fixes = []string{"Use -all or ~all instead of ?all."}
	default: // "-" or "~"
		r.Status = Pass
	}

	if lookups > 10 {
		r.Status = worst(r.Status, Fail)
		r.penalty += 12
		r.Findings = append(r.Findings, "over the 10-lookup limit: strict receivers will treat SPF as permerror")
		r.Fixes = append(r.Fixes, "Flatten or remove includes to get under 10 DNS lookups.")
	}
	return r
}

// countSPFLookups counts the DNS-lookup-incurring mechanisms in an SPF record,
// following include and redirect targets recursively (guarding against loops and
// runaway depth). This mirrors how a receiver enforces the limit.
func (s *Scanner) countSPFLookups(txt string, seen map[string]bool, depth int) int {
	if depth > 12 {
		return 0
	}
	spf, ok := records.ParseSPF(txt)
	if !ok {
		return 0
	}
	count := 0
	for _, m := range spf.Mechanisms {
		kind, target, counts := records.LookupTerm(m)
		if !counts {
			continue
		}
		count++
		if kind == "include" && target != "" && !seen[target] {
			seen[target] = true
			if sub, ok := s.firstTXT(target, isSPF); ok {
				count += s.countSPFLookups(sub, seen, depth+1)
			}
		}
	}
	if spf.Redirect != "" && !seen[spf.Redirect] {
		count++
		seen[spf.Redirect] = true
		if sub, ok := s.firstTXT(spf.Redirect, isSPF); ok {
			count += s.countSPFLookups(sub, seen, depth+1)
		}
	}
	return count
}

func isSPF(t string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1")
}

func allDesc(q string) string {
	switch q {
	case "-":
		return "-all (hard fail)"
	case "~":
		return "~all (soft fail)"
	case "?":
		return "?all (neutral)"
	case "+":
		return "+all (pass any)"
	default:
		return "no all mechanism"
	}
}

// worst returns the more severe of two statuses (Fail > Warn > Pass).
func worst(a, b Status) Status {
	sev := func(s Status) int {
		switch s {
		case Fail:
			return 3
		case Warn:
			return 2
		case Pass:
			return 1
		default:
			return 0
		}
	}
	if sev(b) > sev(a) {
		return b
	}
	return a
}
