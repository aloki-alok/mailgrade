package checks

import (
	"fmt"
	"strings"

	"github.com/aloki-alok/mailgrade/internal/records"
)

// hasP reports whether a TXT record looks like a DKIM key record (it carries a
// p= public-key tag).
func hasP(t string) bool { return strings.Contains(strings.ToLower(t), "p=") }

// commonSelectors are DKIM selector names in wide use by mail providers. DKIM
// gives no way to enumerate selectors from DNS, so discovery probes these (plus
// any user-supplied --selector).
var commonSelectors = []string{
	"google", "selector1", "selector2", "s1", "s2", "k1", "k2", "k3",
	"default", "dkim", "mail", "smtp", "mandrill", "mxvault", "protonmail",
	"protonmail2", "protonmail3", "zoho", "zohomail", "fm1", "fm2", "fm3",
	"sig1", "scph0122", "pic", "amazonses", "mailjet", "sparkpost",
}

// checkDKIM probes common selectors (and any override) for a DKIM key and reports
// the first working one, its size, and any weakness (undersized, testing, revoked).
func (s *Scanner) checkDKIM() Result {
	r := Result{Name: "DKIM"}

	// A wildcard under _domainkey answers every selector, so per-selector
	// discovery would report a meaningless "found". Detect it by probing a name
	// that cannot be a real selector.
	if _, ok := s.firstTXT("mailgrade-wildcard-probe._domainkey."+s.domain, hasP); ok {
		r.Status = NA
		r.Summary = "wildcard _domainkey record: every selector answers"
		r.Findings = []string{"a specific selector cannot be verified; check DKIM at your provider"}
		return r
	}

	selectors := commonSelectors
	if s.opts.Selector != "" {
		selectors = append([]string{s.opts.Selector}, selectors...)
	}

	for _, sel := range selectors {
		name := sel + "._domainkey." + s.domain
		txt, ok := s.firstTXT(name, hasP)
		if !ok {
			continue
		}
		dkim, ok := records.ParseDKIM(txt)
		if !ok {
			continue
		}
		r.Summary = fmt.Sprintf("selector %q found", sel)

		switch {
		case dkim.Revoked:
			r.Status = Fail
			r.penalty = 15
			r.Findings = append(r.Findings, fmt.Sprintf("selector %q is published but revoked (empty p=)", sel))
			r.Fixes = []string{"Publish a valid public key for an active selector, or remove the revoked record."}
		case dkim.Testing:
			r.Status = Warn
			r.penalty = 6
			r.Findings = append(r.Findings, "the t=y testing flag is set, so receivers may ignore DKIM results")
			r.Fixes = []string{"Remove the t=y flag once you have verified signing works."}
		case dkim.KeyType == "rsa" && dkim.Bits > 0 && dkim.Bits < 1024:
			r.Status = Warn
			r.penalty = 8
			r.Findings = append(r.Findings, fmt.Sprintf("RSA key is only %d bits", dkim.Bits))
			r.Fixes = []string{"Rotate to a 2048-bit RSA key."}
		default:
			r.Status = Pass
			if dkim.Bits > 0 {
				r.Findings = append(r.Findings, fmt.Sprintf("%s key, %d bits", strings.ToUpper(dkim.KeyType), dkim.Bits))
			}
		}
		return r
	}

	// DKIM selectors cannot be enumerated from DNS, so a miss is inconclusive,
	// not proof of absence: penalize moderately and say so, rather than declaring
	// a domain broken when it may just use a selector we did not guess.
	r.Status = Warn
	r.penalty = 8
	r.Summary = "no DKIM selector found among common names"
	r.Findings = []string{"selectors cannot be listed from DNS; the domain may sign with a custom one"}
	r.Fixes = []string{
		"If you use a custom selector, re-run with --selector <name> to confirm.",
		"If you do not sign with DKIM, enable it at your mail provider and publish its selector record.",
	}
	return r
}
