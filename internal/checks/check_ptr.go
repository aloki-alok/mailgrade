package checks

import (
	"fmt"
	"net"
	"strings"
)

// checkPTR verifies that each MX IP has reverse DNS that forward-confirms: the
// PTR name must itself resolve back to the same IP (FCrDNS). Receiving servers
// weight forward-confirmed reverse DNS heavily.
func (s *Scanner) checkPTR() Result {
	r := Result{Name: "PTR / rDNS"}

	ips := s.allMXIPs()
	for _, ip := range s.opts.SendingIPs {
		if parsed := net.ParseIP(ip); parsed != nil {
			ips = append(ips, parsed)
		}
	}
	if len(ips) == 0 {
		r.Status = NA
		r.Summary = "no MX addresses to check"
		return r
	}

	confirmed, total := 0, 0
	for _, ip := range ips {
		total++
		names, err := s.res.PTR(ip)
		if err != nil || len(names) == 0 {
			r.Findings = append(r.Findings, fmt.Sprintf("%s has no PTR record", ip))
			continue
		}
		if s.forwardConfirms(names, ip) {
			confirmed++
			r.Findings = append(r.Findings, fmt.Sprintf("%s -> %s (confirmed)", ip, names[0]))
		} else {
			r.Findings = append(r.Findings, fmt.Sprintf("%s -> %s (does not forward-confirm)", ip, names[0]))
		}
	}

	switch {
	case confirmed == total:
		r.Status = Pass
		r.Summary = fmt.Sprintf("all %d MX address(es) have forward-confirmed rDNS", total)
	case confirmed > 0:
		r.Status = Warn
		r.penalty = 6
		r.Summary = fmt.Sprintf("%d of %d MX addresses have forward-confirmed rDNS", confirmed, total)
		r.Fixes = []string{"Set a PTR record for each sending IP that resolves back to that same IP."}
	default:
		r.Status = Fail
		r.penalty = 10
		r.Summary = "no MX address has forward-confirmed reverse DNS"
		r.Fixes = []string{"Ask your host to set PTR records; each must resolve forward to the same IP."}
	}
	return r
}

func (s *Scanner) forwardConfirms(names []string, ip net.IP) bool {
	for _, name := range names {
		fwd, err := s.res.IPs(strings.TrimSuffix(name, "."))
		if err != nil {
			continue
		}
		for _, f := range fwd {
			if f.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) allMXIPs() []net.IP {
	var out []net.IP
	for _, m := range s.mx {
		out = append(out, s.mxIPs[m.Host]...)
	}
	return out
}
