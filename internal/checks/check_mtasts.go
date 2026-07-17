package checks

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aloki-alok/mailgrade/internal/records"
)

// checkMTASTS confirms both halves of MTA-STS: the _mta-sts TXT record and the
// policy file served over HTTPS, and reports the policy mode.
func (s *Scanner) checkMTASTS() Result {
	r := Result{Name: "MTA-STS"}

	_, hasTXT := s.firstTXT("_mta-sts."+s.domain, func(t string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=stsv1")
	})
	if !hasTXT {
		r.Status = Warn
		r.penalty = 4
		r.Summary = "no MTA-STS policy"
		r.Fixes = []string{"Publish an _mta-sts TXT record and serve a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt to require TLS."}
		return r
	}

	body, err := fetchPolicy(s.domain, s.opts.Timeout)
	if err != nil {
		r.Status = Warn
		r.penalty = 3
		r.Summary = "MTA-STS record present but the policy file did not load"
		r.Findings = []string{err.Error()}
		r.Fixes = []string{"Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt."}
		return r
	}
	policy, ok := records.ParseMTASTSPolicy(body)
	if !ok {
		r.Status = Warn
		r.penalty = 3
		r.Summary = "MTA-STS policy file is malformed"
		r.Fixes = []string{"The policy must declare version: STSv1 and a mode."}
		return r
	}

	r.Summary = "MTA-STS mode " + orNone(policy.Mode)
	switch policy.Mode {
	case "enforce":
		r.Status = Pass
	case "testing":
		r.Status = Warn
		r.penalty = 2
		r.Findings = []string{"mode is testing, so TLS is not yet required"}
		r.Fixes = []string{"Move the policy to mode: enforce once testing reports look clean."}
	default:
		r.Status = Warn
		r.penalty = 3
		r.Findings = []string{"mode is none, so the policy has no effect"}
		r.Fixes = []string{"Set mode: enforce (or testing) in the policy."}
	}
	return r
}

func fetchPolicy(domain string, timeout time.Duration) (string, error) {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	client := &http.Client{Timeout: timeout + 3*time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("policy returned status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
