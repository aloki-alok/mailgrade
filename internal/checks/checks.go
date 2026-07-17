// Package checks runs a domain's mail-posture checks and scores them. Each
// check resolves the records it needs, applies a pure parser from the records
// package, and returns a Result with a status, findings, and the fix to apply.
// A Scanner threads data discovered early (the MX hosts and their IPs) into the
// later checks that need it.
package checks

import (
	"net"
	"time"

	"github.com/aloki-alok/mailgrade/internal/dns"
)

// Status is the outcome of a single check.
type Status int

const (
	// Pass: configured well.
	Pass Status = iota
	// Warn: works but weak (for example DMARC p=none).
	Warn
	// Fail: missing or broken, and it affects deliverability.
	Fail
	// NA: legitimately not applicable (for example BIMI, or no MX on a
	// non-sending domain). Never penalized.
	NA
	// Skip: could not test from this machine (for example port 25 blocked).
	// Never penalized, since it reflects the runner, not the domain.
	Skip
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "pass"
	case Warn:
		return "warn"
	case Fail:
		return "fail"
	case NA:
		return "na"
	default:
		return "skip"
	}
}

// Result is one check's outcome.
type Result struct {
	Name     string   `json:"name"`
	Status   Status   `json:"status"`
	Summary  string   `json:"summary"`
	Findings []string `json:"findings,omitempty"`
	Fixes    []string `json:"fixes,omitempty"`
	// penalty is the points this result subtracts from 100. Set by each check.
	penalty int
}

// Report is a full scan of one domain.
type Report struct {
	Domain  string   `json:"domain"`
	Results []Result `json:"results"`
	Score   int      `json:"score"`
	Grade   string   `json:"grade"`
}

// Options tunes a scan.
type Options struct {
	Resolver    string        // pinned nameserver, or "" for the system resolver
	Selector    string        // DKIM selector override
	Timeout     time.Duration // per-lookup timeout
	SkipNetwork bool          // skip checks that open TCP connections (MX reachability, STARTTLS)
	SendingIPs  []string      // extra IPs to reverse-check and run against blocklists
}

// Scanner holds a scan's shared state: the resolver and the MX data the MX
// check discovers for the reachability, PTR, STARTTLS, and DANE checks to reuse.
type Scanner struct {
	domain string
	res    *dns.Resolver
	opts   Options

	mx     []dns.MXHost
	mxIPs  map[string][]net.IP
	nullMX bool
}

// Run scans a domain and returns a scored report. Checks run in a fixed order;
// the MX check runs first because later checks reuse its discovered hosts.
func Run(domain string, opts Options) Report {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	s := &Scanner{
		domain: domain,
		res:    dns.New(opts.Resolver, opts.Timeout),
		opts:   opts,
		mxIPs:  map[string][]net.IP{},
	}

	results := []Result{
		s.checkMX(),
		s.checkSPF(),
		s.checkDKIM(),
		s.checkDMARC(),
		s.checkPTR(),
		s.checkSTARTTLS(),
		s.checkMTASTS(),
		s.checkTLSRPT(),
		s.checkDANE(),
		s.checkBIMI(),
		s.checkDNSBL(),
	}

	score, grade := scoreOf(results)
	return Report{Domain: domain, Results: results, Score: score, Grade: grade}
}

// scoreOf sums the per-result penalties, floors the score at 0, and grades it.
func scoreOf(results []Result) (int, string) {
	score := 100
	for _, r := range results {
		score -= r.penalty
	}
	if score < 0 {
		score = 0
	}
	return score, letter(score)
}

func letter(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// smtpTimeout is the dial timeout for port-25 connections. It is longer than the
// per-lookup DNS timeout because mail servers commonly throttle SMTP connections
// from unfamiliar IPs, so a short timeout would skip reachable hosts.
func (s *Scanner) smtpTimeout() time.Duration {
	if s.opts.Timeout > 10*time.Second {
		return s.opts.Timeout
	}
	return 10 * time.Second
}

// firstTXT returns the first TXT record at name matching pred, or "" and false.
func (s *Scanner) firstTXT(name string, pred func(string) bool) (string, bool) {
	recs, err := s.res.TXT(name)
	if err != nil {
		return "", false
	}
	for _, r := range recs {
		if pred(r) {
			return r, true
		}
	}
	return "", false
}
