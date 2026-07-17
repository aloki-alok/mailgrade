package cli

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":              "example.com",
		"Example.COM":              "example.com",
		"https://example.com/path": "example.com",
		"user@example.com":         "example.com",
		"http://example.com":       "example.com",
		"example.com.":             "example.com",
		"  example.com  ":          "example.com",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q want %q", in, got, want)
		}
	}
}

func TestParseFlags(t *testing.T) {
	f, err := parse([]string{"example.com", "--selector", "google", "--json", "--fail-on", "warn"})
	if err != nil {
		t.Fatal(err)
	}
	if f.domain != "example.com" || f.opts.Selector != "google" || !f.jsonOut || !f.hasFail {
		t.Fatalf("unexpected parse: %+v", f)
	}
	if _, err := parse([]string{"--json"}); err == nil {
		t.Error("expected error when no domain given")
	}
	if _, err := parse([]string{"example.com", "--fail-on", "bogus"}); err == nil {
		t.Error("expected error on bad --fail-on")
	}
}
