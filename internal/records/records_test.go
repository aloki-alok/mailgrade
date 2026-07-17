package records

import "testing"

func TestParseSPF(t *testing.T) {
	cases := []struct {
		txt      string
		ok       bool
		allQual  string
		redirect string
		mechs    int
	}{
		{"v=spf1 include:_spf.google.com ~all", true, "~", "", 1},
		{"v=spf1 mx a -all", true, "-", "", 2},
		{"v=spf1 +all", true, "+", "", 0},
		{"v=spf1 all", true, "+", "", 0},
		{"v=spf1 redirect=_spf.example.com", true, "", "_spf.example.com", 0},
		{"v=DKIM1; p=abc", false, "", "", 0},
		{"", false, "", "", 0},
	}
	for _, c := range cases {
		got, ok := ParseSPF(c.txt)
		if ok != c.ok {
			t.Fatalf("ParseSPF(%q) ok=%v want %v", c.txt, ok, c.ok)
		}
		if !ok {
			continue
		}
		if got.AllQualifier != c.allQual {
			t.Errorf("ParseSPF(%q) all=%q want %q", c.txt, got.AllQualifier, c.allQual)
		}
		if got.Redirect != c.redirect {
			t.Errorf("ParseSPF(%q) redirect=%q want %q", c.txt, got.Redirect, c.redirect)
		}
		if len(got.Mechanisms) != c.mechs {
			t.Errorf("ParseSPF(%q) mechs=%d want %d", c.txt, len(got.Mechanisms), c.mechs)
		}
	}
}

func TestLookupTerm(t *testing.T) {
	cases := []struct {
		mech   string
		kind   string
		target string
		counts bool
	}{
		{"include:_spf.google.com", "include", "_spf.google.com", true},
		{"mx", "mx", "", true},
		{"a:mail.example.com", "a", "mail.example.com", true},
		{"ip4:1.2.3.0/24", "", "", false},
		{"-all", "", "", false},
		{"exists:%{i}.spf.example.com", "exists", "%{i}.spf.example.com", true},
	}
	for _, c := range cases {
		kind, target, counts := LookupTerm(c.mech)
		if counts != c.counts || kind != c.kind || target != c.target {
			t.Errorf("LookupTerm(%q) = (%q,%q,%v) want (%q,%q,%v)", c.mech, kind, target, counts, c.kind, c.target, c.counts)
		}
	}
}

func TestParseDMARC(t *testing.T) {
	d, ok := ParseDMARC("v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com")
	if !ok {
		t.Fatal("expected valid DMARC")
	}
	if d.Policy != "reject" || d.SubdomainPolicy != "quarantine" || d.Pct != "100" {
		t.Errorf("bad parse: %+v", d)
	}
	if d.RUA != "mailto:dmarc@example.com" {
		t.Errorf("rua=%q", d.RUA)
	}
	if _, ok := ParseDMARC("v=spf1 -all"); ok {
		t.Error("SPF should not parse as DMARC")
	}
}

func TestParseDKIM(t *testing.T) {
	// A real 1024-bit RSA public key (base64 SubjectPublicKeyInfo), so the key-size
	// path (x509 decode -> modulus bit length) is exercised on a genuine key.
	const key1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhwdCTrhga9K3XE6fi1ZAIzOGVBrL+UhESk0iDTHFUltIz7eRzLtU4KekgR41mMOfst1biEaneIFGmPkoUW93Nlnz+Oru+9S78bTij0bcrfld1/hirTRCrvaqorSa/3IWzAV1vpjxwqnFmExzjwmcxn7DSZT2mreHJRT0rVTWGsQIDAQAB"

	valid, ok := ParseDKIM("v=DKIM1; k=rsa; p=" + key1024)
	if !ok {
		t.Fatal("expected valid DKIM")
	}
	if valid.Bits != 1024 {
		t.Errorf("Bits=%d want 1024", valid.Bits)
	}

	// Revoked key (empty p=).
	rev, ok := ParseDKIM("v=DKIM1; k=rsa; p=")
	if !ok || !rev.Revoked {
		t.Fatalf("expected revoked DKIM, got ok=%v %+v", ok, rev)
	}

	testing_, ok := ParseDKIM("v=DKIM1; k=rsa; t=y; p=" + key1024)
	if !ok || !testing_.Testing {
		t.Fatalf("expected testing flag set, got %+v", testing_)
	}

	if _, ok := ParseDKIM("v=DKIM1; k=rsa"); ok {
		t.Error("a record with no p= is not a usable DKIM key")
	}
}

func TestParseMTASTSPolicy(t *testing.T) {
	body := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n"
	p, ok := ParseMTASTSPolicy(body)
	if !ok {
		t.Fatal("expected valid policy")
	}
	if p.Mode != "enforce" || len(p.MX) != 2 || p.MaxAge != "604800" {
		t.Errorf("bad policy parse: %+v", p)
	}
	if _, ok := ParseMTASTSPolicy("mode: enforce\n"); ok {
		t.Error("policy without version should not parse")
	}
}
