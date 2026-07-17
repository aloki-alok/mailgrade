package checks

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/aloki-alok/mailgrade/internal/dns"
)

// checkTLSRPT reports whether the domain publishes an SMTP TLS reporting policy,
// which is how you learn when TLS delivery to your domain fails.
func (s *Scanner) checkTLSRPT() Result {
	r := Result{Name: "TLS-RPT"}
	if s.nullMX {
		r.Status = NA
		r.Summary = "not applicable: domain receives no mail"
		return r
	}
	_, ok := s.firstTXT("_smtp._tls."+s.domain, func(t string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=tlsrptv1")
	})
	if ok {
		r.Status = Pass
		r.Summary = "SMTP TLS reporting is configured"
		return r
	}
	r.Status = Warn
	r.penalty = 3
	r.Summary = "no TLS-RPT record"
	r.Fixes = []string{`Publish _smtp._tls TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com" to receive TLS failure reports.`}
	return r
}

// checkDANE reports whether the primary MX publishes TLSA records (DANE). DANE
// is an optional hardening layer, so its absence is informational, not a
// penalty. The lookup is over DNS-over-HTTPS and best-effort.
func (s *Scanner) checkDANE() Result {
	r := Result{Name: "DANE"}
	if len(s.mx) == 0 {
		r.Status = NA
		r.Summary = "no MX to check"
		return r
	}
	host := s.mx[0].Host
	tlsa, err := s.res.TLSA("_25._tcp." + host)
	if err != nil {
		r.Status = NA
		r.Summary = "could not determine DANE (optional)"
		return r
	}
	if len(tlsa) > 0 {
		r.Status = Pass
		r.Summary = fmt.Sprintf("%d TLSA record(s) on %s", len(tlsa), host)
		return r
	}
	r.Status = NA
	r.Summary = "no TLSA records (DANE is optional)"
	r.Fixes = []string{"Optionally publish _25._tcp TLSA records to pin your MX certificate (requires DNSSEC)."}
	return r
}

// checkBIMI reports whether the domain publishes a BIMI logo record. BIMI is
// optional and cosmetic, so its absence is never penalized.
func (s *Scanner) checkBIMI() Result {
	r := Result{Name: "BIMI"}
	txt, ok := s.firstTXT("default._bimi."+s.domain, func(t string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=bimi1")
	})
	if ok {
		r.Status = Pass
		r.Summary = "BIMI logo record published"
		if strings.Contains(strings.ToLower(txt), "a=") {
			r.Findings = []string{"includes a VMC (verified mark certificate)"}
		}
		return r
	}
	r.Status = NA
	r.Summary = "no BIMI record (optional)"
	r.Fixes = []string{"Optionally publish a default._bimi record to show your logo in supporting clients (requires DMARC enforcement)."}
	return r
}

// dnsbls are well-known DNS blocklists queried by reversed-IP lookup.
var dnsbls = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"dnsbl.sorbs.net",
}

// checkDNSBL looks up each MX IP (and any provided sending IP) against well-known
// blocklists. A blocklist answers in 127.0.0.0/24: codes like 127.0.0.2-11 mean
// listed, while 127.255.255.x means the query itself was refused (which public
// resolvers commonly trigger). Only a genuine listing counts; if every zone
// refuses the query the check is inconclusive, never a false failure.
func (s *Scanner) checkDNSBL() Result {
	r := Result{Name: "Blocklists"}
	ips := s.allMXIPs()
	for _, ip := range s.opts.SendingIPs {
		if p := net.ParseIP(ip); p != nil {
			ips = append(ips, p)
		}
	}
	if len(ips) == 0 {
		r.Status = NA
		r.Summary = "no IPs to check"
		return r
	}

	type probe struct {
		ip   net.IP
		zone string
	}
	var jobs []probe
	for _, ip := range ips {
		if _, ok := dns.ReverseName(ip); !ok {
			continue // IPv6 blocklist queries are out of scope for v0.1
		}
		for _, zone := range dnsbls {
			jobs = append(jobs, probe{ip, zone})
		}
	}

	type outcome struct {
		listed  bool
		clean   bool
		listing string
	}
	outcomes := make([]outcome, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j probe) {
			defer wg.Done()
			rev, _ := dns.ReverseName(j.ip)
			switch classifyDNSBL(s, rev+"."+j.zone) {
			case dnsblListed:
				outcomes[i] = outcome{listed: true, clean: true, listing: fmt.Sprintf("%s listed on %s", j.ip, j.zone)}
			case dnsblClean:
				outcomes[i] = outcome{clean: true}
			}
		}(i, j)
	}
	wg.Wait()

	var listings []string
	definitive := 0
	probes := len(jobs)
	for _, o := range outcomes {
		if o.clean {
			definitive++
		}
		if o.listed {
			listings = append(listings, o.listing)
		}
	}

	switch {
	case len(listings) > 0:
		r.Status = Fail
		r.penalty = 15
		r.Summary = fmt.Sprintf("%d blocklist listing(s)", len(listings))
		r.Findings = listings
		r.Fixes = []string{"Request delisting at each blocklist after fixing the cause (open relay, compromised host, poor sending practice)."}
	case definitive == 0:
		r.Status = NA
		r.Summary = "blocklists did not answer (this resolver may be rate-limited)"
		r.Findings = []string{"query a private or dedicated resolver with --resolver for a reliable result"}
	default:
		r.Status = Pass
		r.Summary = fmt.Sprintf("not listed (%d of %d zone lookups answered)", definitive, probes)
	}
	return r
}

type dnsblOutcome int

const (
	dnsblBlocked dnsblOutcome = iota // query refused / rate-limited (inconclusive)
	dnsblClean                       // authoritative "not listed"
	dnsblListed                      // genuinely listed
)

// classifyDNSBL interprets a blocklist lookup. A missing record (NXDOMAIN) is a
// clean answer; the returned addresses are classified by dnsblFromIPs.
func classifyDNSBL(s *Scanner, name string) dnsblOutcome {
	ips, err := s.res.IPs(name)
	if err != nil {
		return dnsblClean // NXDOMAIN and the like: not listed
	}
	return dnsblFromIPs(ips)
}

// dnsblFromIPs classifies a blocklist's answer addresses: an address in
// 127.0.0.2-254 is a listing; 127.255.255.x (and anything else) is a query
// refusal, treated as inconclusive rather than a listing.
func dnsblFromIPs(ips []net.IP) dnsblOutcome {
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil || v4[0] != 127 {
			continue
		}
		if v4[1] == 255 && v4[2] == 255 {
			return dnsblBlocked // Spamhaus-style "query blocked" code
		}
		if v4[1] == 0 && v4[2] == 0 && v4[3] >= 2 && v4[3] < 255 {
			return dnsblListed
		}
	}
	return dnsblBlocked
}
