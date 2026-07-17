package checks

import (
	"fmt"
	"net"
	"time"
)

// checkMX resolves the domain's MX records, resolves each host's IPs, and (unless
// network is skipped) probes port 25 to confirm at least one is reachable. It
// stores the discovered hosts and IPs for the PTR, STARTTLS, and DANE checks.
func (s *Scanner) checkMX() Result {
	r := Result{Name: "MX"}
	mx, err := s.res.MX(s.domain)
	if err != nil || len(mx) == 0 {
		r.Status = Fail
		r.penalty = 25
		r.Summary = "no MX records: this domain cannot receive mail"
		r.Fixes = []string{"Publish at least one MX record pointing at a mail host that accepts SMTP on port 25."}
		return r
	}
	s.mx = mx

	hosts := make([]string, 0, len(mx))
	reachable := 0
	for _, m := range mx {
		hosts = append(hosts, fmt.Sprintf("%s (pref %d)", m.Host, m.Pref))
		ips, err := s.res.IPs(m.Host)
		if err != nil || len(ips) == 0 {
			r.Findings = append(r.Findings, fmt.Sprintf("%s does not resolve to an address", m.Host))
			continue
		}
		s.mxIPs[m.Host] = ips
		if s.opts.SkipNetwork {
			continue
		}
		if dialable(s.dialTarget(m.Host), s.smtpTimeout()) {
			reachable++
		} else {
			r.Findings = append(r.Findings, fmt.Sprintf("%s is not reachable on port 25", m.Host))
		}
	}

	r.Summary = fmt.Sprintf("%d MX host(s): %s", len(mx), joinShort(hosts))

	switch {
	case len(s.mxIPs) == 0:
		r.Status = Fail
		r.penalty = 20
		r.Summary = "MX records exist but none resolve to an address"
		r.Fixes = []string{"Point each MX record at a hostname that has an A/AAAA record."}
	case s.opts.SkipNetwork:
		r.Status = Pass
	case reachable == 0:
		// Could not reach any host on 25. This is often the runner's network
		// (outbound 25 blocked), so do not penalize; flag it as a skip.
		r.Status = Skip
		r.Findings = append(r.Findings, "could not connect to any MX on port 25 (outbound 25 may be blocked here)")
	default:
		r.Status = Pass
	}
	return r
}

// dialable reports whether a TCP connection to addr succeeds within timeout.
func dialable(addr string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func joinShort(items []string) string {
	const max = 3
	if len(items) <= max {
		return join(items)
	}
	return join(items[:max]) + fmt.Sprintf(" (+%d more)", len(items)-max)
}

func join(items []string) string {
	out := ""
	for i, it := range items {
		if i > 0 {
			out += ", "
		}
		out += it
	}
	return out
}
