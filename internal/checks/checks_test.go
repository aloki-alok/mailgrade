package checks

import (
	"net"
	"testing"
)

func TestScoreOfAndGrade(t *testing.T) {
	cases := []struct {
		name      string
		penalties []int
		want      int
		grade     string
	}{
		{"clean", nil, 100, "A"},
		{"one warn", []int{10}, 90, "A"},
		{"b range", []int{10, 8}, 82, "B"},
		{"floors at zero", []int{60, 60}, 0, "F"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var results []Result
			for _, p := range c.penalties {
				results = append(results, Result{penalty: p})
			}
			score, grade := scoreOf(results)
			if score != c.want || grade != c.grade {
				t.Fatalf("got %d/%s want %d/%s", score, grade, c.want, c.grade)
			}
		})
	}
}

func TestDnsblFromIPs(t *testing.T) {
	cases := []struct {
		name string
		ips  []net.IP
		want dnsblOutcome
	}{
		{"listed 127.0.0.2", []net.IP{net.ParseIP("127.0.0.2")}, dnsblListed},
		{"listed 127.0.0.11", []net.IP{net.ParseIP("127.0.0.11")}, dnsblListed},
		{"blocked 127.255.255.254", []net.IP{net.ParseIP("127.255.255.254")}, dnsblBlocked},
		{"unexpected public IP", []net.IP{net.ParseIP("1.2.3.4")}, dnsblBlocked},
		{"empty", nil, dnsblBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dnsblFromIPs(c.ips); got != c.want {
				t.Fatalf("dnsblFromIPs(%v) = %d want %d", c.ips, got, c.want)
			}
		})
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		name    string
		grade   string
		results []Result
		want    string
	}{
		{
			"clean", "A",
			[]Result{{Name: "MX", Status: Pass}, {Name: "SPF", Status: Pass}},
			"Locked down. Nothing to fix.",
		},
		{
			"failing names top priority first", "F",
			[]Result{{Name: "DKIM", Status: Fail}, {Name: "MX", Status: Fail}, {Name: "SPF", Status: Fail}},
			"Not inbox-ready: fix MX and SPF first.",
		},
		{
			"grade A with hardening warns", "A",
			[]Result{{Name: "MX", Status: Pass}, {Name: "MTA-STS", Status: Warn}, {Name: "TLS-RPT", Status: Warn}},
			"Solid. 2 quick wins to harden (start with MTA-STS).",
		},
		{
			"weak grade with warns", "D",
			[]Result{{Name: "DMARC", Status: Warn}},
			"Needs work: 1 issue (start with DMARC).",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Report{Grade: c.grade, Results: c.results}
			if got := r.Verdict(); got != c.want {
				t.Fatalf("Verdict() = %q want %q", got, c.want)
			}
		})
	}
}

func TestWorst(t *testing.T) {
	if worst(Pass, Fail) != Fail {
		t.Error("Fail should beat Pass")
	}
	if worst(Warn, Pass) != Warn {
		t.Error("Warn should beat Pass")
	}
	if worst(Fail, Warn) != Fail {
		t.Error("Fail should beat Warn")
	}
}
