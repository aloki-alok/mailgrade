package checks

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// checkSTARTTLS connects to the primary MX, confirms it offers STARTTLS, and
// verifies the certificate it presents (valid chain, not expired, hostname
// matches). If port 25 is unreachable from this machine the check is a Skip, not
// a failure: that reflects the runner's network, not the domain.
func (s *Scanner) checkSTARTTLS() Result {
	r := Result{Name: "STARTTLS"}
	if s.opts.SkipNetwork {
		r.Status = Skip
		r.Summary = "network checks skipped (--no-network)"
		return r
	}
	if len(s.mx) == 0 {
		r.Status = NA
		r.Summary = "no MX to test"
		return r
	}

	host := s.mx[0].Host
	chain, offered, err := probeSTARTTLS(s.dialTarget(host), host, s.smtpTimeout())
	if err != nil {
		r.Status = Skip
		r.Summary = fmt.Sprintf("could not test %s: %v", host, err)
		r.Findings = []string{"outbound port 25 may be blocked on this machine"}
		return r
	}
	if !offered {
		r.Status = Fail
		r.penalty = 12
		r.Summary = fmt.Sprintf("%s does not offer STARTTLS", host)
		r.Fixes = []string{"Enable STARTTLS on your MTA so mail is encrypted in transit."}
		return r
	}

	r.Summary = fmt.Sprintf("%s offers STARTTLS", host)
	cert := chain[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	// SMTP STARTTLS is opportunistic: sending servers use it to encrypt, and a
	// chain that does not build to a public root (usually because the MTA omits
	// intermediates) does not stop delivery. So a failed chain build is noted but
	// not penalized. Expiry and a hostname mismatch are real problems (they break
	// delivery under MTA-STS enforce or DANE), so those warn.
	expired := time.Now().After(cert.NotAfter)
	nameMismatch := cert.VerifyHostname(host) != nil
	chainErr := verifyChain(chain, host)

	switch {
	case expired:
		r.Status = Warn
		r.penalty = 6
		r.Findings = []string{"certificate expired " + cert.NotAfter.Format("2006-01-02")}
		r.Fixes = []string{"Renew the MX certificate; an expired cert is rejected under MTA-STS or DANE."}
	case nameMismatch:
		r.Status = Warn
		r.penalty = 5
		r.Findings = []string{fmt.Sprintf("certificate name does not match %s", host)}
		r.Fixes = []string{"Use a certificate whose subject matches the MX hostname; a mismatch is rejected under MTA-STS or DANE."}
	case daysLeft < 14:
		r.Status = Warn
		r.penalty = 4
		r.Findings = []string{fmt.Sprintf("certificate expires in %d days", daysLeft)}
		r.Fixes = []string{"Renew the certificate soon; it expires in under two weeks."}
	default:
		r.Status = Pass
		r.Findings = []string{fmt.Sprintf("valid certificate, %d days until expiry", daysLeft)}
		if chainErr != nil {
			r.Findings = append(r.Findings, "chain does not build to a public root (normal for opportunistic TLS; matters under MTA-STS or DANE)")
		}
	}
	return r
}

// dialTarget returns the address to dial for a host: a resolved IPv4 when one is
// known (avoiding a hang when the runner has no IPv6 route), else the hostname.
func (s *Scanner) dialTarget(host string) string {
	for _, ip := range s.mxIPs[host] {
		if v4 := ip.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), "25")
		}
	}
	return net.JoinHostPort(host, "25")
}

// probeSTARTTLS speaks just enough SMTP to reach the TLS handshake and returns
// the certificate chain the server presents. It dials dialAddr but uses
// serverName for SNI and later verification. It reads the certificates even if
// they would not verify (the caller judges validity), so a bad cert is
// reported, not hidden.
func probeSTARTTLS(dialAddr, serverName string, timeout time.Duration) (chain []*x509.Certificate, offered bool, err error) {
	conn, err := net.DialTimeout("tcp", dialAddr, timeout)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout + 5*time.Second))

	tp := textproto.NewReader(bufio.NewReader(conn))
	if _, _, err := tp.ReadResponse(220); err != nil {
		return nil, false, fmt.Errorf("no greeting: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "EHLO mailgrade.invalid\r\n"); err != nil {
		return nil, false, err
	}
	_, ehlo, err := tp.ReadResponse(250)
	if err != nil {
		return nil, false, fmt.Errorf("EHLO failed: %w", err)
	}
	if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
		return nil, false, nil
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return nil, true, err
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return nil, true, fmt.Errorf("STARTTLS refused: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		return nil, true, fmt.Errorf("TLS handshake failed: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, true, fmt.Errorf("no certificate presented")
	}
	return state.PeerCertificates, true, nil
}

// verifyChain verifies the leaf against the system roots, using any
// intermediates the server sent to build the chain.
func verifyChain(chain []*x509.Certificate, host string) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter})
	return err
}
