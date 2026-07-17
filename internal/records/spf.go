// Package records holds pure parsers for the DNS records a mail-posture scan
// inspects: SPF, DMARC, DKIM, and the MTA-STS policy. Each parser turns a raw
// record string into a typed value with no I/O, so the parsing logic is fully
// table-testable. The checks package resolves DNS and applies these parsers.
package records

import "strings"

// SPF is a parsed v=spf1 record.
type SPF struct {
	Raw string
	// Mechanisms are the SPF terms in order (for example "include:_spf.google.com",
	// "mx", "a", "-all").
	Mechanisms []string
	// AllQualifier is the qualifier on the final `all` mechanism: "-", "~", "?",
	// "+", or "" when there is no `all`.
	AllQualifier string
	// Redirect is the target of a redirect= modifier, if present.
	Redirect string
}

// spfLookupMechanisms are the terms that each cost one of SPF's ten DNS lookups
// (RFC 7208 §4.6.4). Counting them, resolving includes recursively, is how the
// check enforces the limit; the parser exposes the top-level terms.
var spfLookupMechanisms = map[string]bool{
	"include": true, "a": true, "mx": true, "ptr": true, "exists": true,
}

// ParseSPF parses an SPF TXT record. It returns ok=false if the string is not
// an SPF record (does not start with v=spf1).
func ParseSPF(txt string) (SPF, bool) {
	fields := strings.Fields(txt)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return SPF{}, false
	}
	s := SPF{Raw: txt}
	for _, term := range fields[1:] {
		lower := strings.ToLower(term)
		switch {
		case lower == "all" || (len(term) > 3 && lower[1:] == "all" && isQualifier(term[0])):
			if isQualifier(term[0]) {
				s.AllQualifier = string(term[0])
			} else {
				s.AllQualifier = "+"
			}
		case strings.HasPrefix(lower, "redirect="):
			s.Redirect = term[len("redirect="):]
		default:
			s.Mechanisms = append(s.Mechanisms, term)
		}
	}
	return s, true
}

func isQualifier(b byte) bool {
	return b == '+' || b == '-' || b == '~' || b == '?'
}

// LookupTerm reports whether a mechanism costs a DNS lookup and, if so, its
// kind ("include", "a", "mx", "ptr", "exists") and target (the part after ':').
func LookupTerm(mechanism string) (kind, target string, counts bool) {
	m := strings.TrimLeft(mechanism, "+-~?")
	name := m
	if i := strings.IndexAny(m, ":/"); i >= 0 {
		name = m[:i]
	}
	name = strings.ToLower(name)
	if !spfLookupMechanisms[name] {
		return "", "", false
	}
	if i := strings.Index(m, ":"); i >= 0 {
		target = m[i+1:]
	}
	return name, target, true
}
