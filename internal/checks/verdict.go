package checks

import (
	"fmt"
	"strings"
)

// priority orders checks by how much they matter for reaching the inbox, so the
// verdict names the most important thing to fix first. Checks not listed here
// (the optional hardening ones) rank after these, in result order.
var priority = []string{"MX", "SPF", "DMARC", "DKIM", "PTR / rDNS", "STARTTLS", "Blocklists"}

// Verdict returns a one-line, plain-English summary of a report: the headline
// problem to fix, or confirmation that the setup is sound.
func (r Report) Verdict() string {
	fails := r.byStatusRanked(Fail)
	warns := r.byStatusRanked(Warn)

	switch {
	case len(fails) > 0:
		return fmt.Sprintf("Not inbox-ready: fix %s first.", humanList(fails, 2))
	case len(warns) > 0 && (r.Grade == "A" || r.Grade == "B"):
		return fmt.Sprintf("Solid. %s to harden (start with %s).", plural(len(warns), "quick win"), warns[0])
	case len(warns) > 0:
		return fmt.Sprintf("Needs work: %s (start with %s).", plural(len(warns), "issue"), warns[0])
	default:
		return "Locked down. Nothing to fix."
	}
}

// byStatusRanked returns the names of checks with status st, ordered by inbox
// impact (priority list first, then any others).
func (r Report) byStatusRanked(st Status) []string {
	rank := map[string]int{}
	for i, name := range priority {
		rank[name] = i
	}
	var names []string
	for _, res := range r.Results {
		if res.Status == st {
			names = append(names, res.Name)
		}
	}
	sort := func(i, j int) bool {
		ri, oki := rank[names[i]]
		rj, okj := rank[names[j]]
		if oki && okj {
			return ri < rj
		}
		return oki && !okj
	}
	// simple insertion sort keeps result order stable for equal ranks
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && sort(j, j-1); j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// humanList joins up to max names as "A, B and C", noting any overflow.
func humanList(items []string, max int) string {
	if len(items) > max {
		items = items[:max]
	}
	switch len(items) {
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
