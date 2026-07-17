package records

import "strings"

// DMARC is a parsed _dmarc TXT record.
type DMARC struct {
	Raw string
	// Policy is the p= tag: "none", "quarantine", or "reject".
	Policy string
	// SubdomainPolicy is the sp= tag, empty when unset (inherits Policy).
	SubdomainPolicy string
	// Pct is the pct= tag as given, empty when unset (defaults to 100).
	Pct string
	// RUA and RUF are the aggregate and forensic reporting addresses.
	RUA string
	RUF string
	// Tags is every tag=value pair for anything not surfaced above.
	Tags map[string]string
}

// ParseDMARC parses a DMARC record. It returns ok=false if the string is not a
// DMARC record (does not start with v=DMARC1).
func ParseDMARC(txt string) (DMARC, bool) {
	tags := parseTags(txt)
	if !strings.EqualFold(tags["v"], "DMARC1") {
		return DMARC{}, false
	}
	return DMARC{
		Raw:             txt,
		Policy:          strings.ToLower(tags["p"]),
		SubdomainPolicy: strings.ToLower(tags["sp"]),
		Pct:             tags["pct"],
		RUA:             tags["rua"],
		RUF:             tags["ruf"],
		Tags:            tags,
	}, true
}

// parseTags splits a semicolon-separated "k=v; k=v" record into a map with
// lower-cased keys and trimmed values.
func parseTags(txt string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}
