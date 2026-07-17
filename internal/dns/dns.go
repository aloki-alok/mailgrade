// Package dns is mailgrade's lookup layer. It wraps the standard resolver for
// the record types it supports (MX, TXT, A/AAAA, PTR), optionally pinned to a
// specific nameserver, and falls back to DNS-over-HTTPS for TLSA records, which
// the standard library cannot query. Every lookup carries a timeout so a scan
// cannot hang on a slow zone.
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// Resolver performs the DNS lookups a mail-posture scan needs.
type Resolver struct {
	r       *net.Resolver
	timeout time.Duration
	server  string // pinned nameserver "host:port", or "" for the system resolver
}

// New returns a Resolver. If server is non-empty (for example "1.1.1.1"), all
// standard lookups go to that nameserver; otherwise the system resolver is used.
func New(server string, timeout time.Duration) *Resolver {
	res := &Resolver{timeout: timeout}
	if server == "" {
		res.r = net.DefaultResolver
		return res
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	res.server = server
	res.r = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, server)
		},
	}
	return res
}

func (r *Resolver) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), r.timeout)
}

// MXHost is one MX record.
type MXHost struct {
	Host string
	Pref uint16
}

// MX returns the domain's MX hosts ordered by preference (lowest first).
func (r *Resolver) MX(domain string) ([]MXHost, error) {
	ctx, cancel := r.ctx()
	defer cancel()
	recs, err := r.r.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := make([]MXHost, 0, len(recs))
	for _, m := range recs {
		out = append(out, MXHost{Host: trimDot(m.Host), Pref: m.Pref})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pref < out[j].Pref })
	return out, nil
}

// TXT returns the TXT records at name, each joined from its character strings.
func (r *Resolver) TXT(name string) ([]string, error) {
	ctx, cancel := r.ctx()
	defer cancel()
	return r.r.LookupTXT(ctx, name)
}

// IPs returns the A/AAAA addresses for host.
func (r *Resolver) IPs(host string) ([]net.IP, error) {
	ctx, cancel := r.ctx()
	defer cancel()
	addrs, err := r.r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// PTR returns the reverse-DNS names for an IP.
func (r *Resolver) PTR(ip net.IP) ([]string, error) {
	ctx, cancel := r.ctx()
	defer cancel()
	names, err := r.r.LookupAddr(ctx, ip.String())
	if err != nil {
		return nil, err
	}
	for i := range names {
		names[i] = trimDot(names[i])
	}
	return names, nil
}

// HostExists reports whether name resolves to any address, used for blocklist
// (DNSBL) probes where the presence of an answer is the signal.
func (r *Resolver) HostExists(name string) (bool, []net.IP) {
	ips, err := r.IPs(name)
	if err != nil || len(ips) == 0 {
		return false, nil
	}
	return true, ips
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// ReverseName builds the reversed dotted-quad label for an IPv4 address, the
// prefix used for both PTR and DNSBL queries (for example 1.2.3.4 -> 4.3.2.1).
func ReverseName(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0]), true
}
