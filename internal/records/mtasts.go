package records

import "strings"

// MTASTSPolicy is a parsed MTA-STS policy file (served at
// https://mta-sts.<domain>/.well-known/mta-sts.txt).
type MTASTSPolicy struct {
	Raw string
	// Mode is "enforce", "testing", or "none".
	Mode string
	// MX is the list of allowed MX patterns (mx: lines), for example
	// "mail.example.com" or "*.example.com".
	MX []string
	// MaxAge is the max_age value in seconds as given, empty when unset.
	MaxAge string
}

// ParseMTASTSPolicy parses the key:value lines of an MTA-STS policy file. It
// returns ok=false if the file does not declare version STSv1.
func ParseMTASTSPolicy(body string) (MTASTSPolicy, bool) {
	p := MTASTSPolicy{Raw: body}
	versionOK := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "version":
			versionOK = strings.EqualFold(v, "STSv1")
		case "mode":
			p.Mode = strings.ToLower(v)
		case "mx":
			p.MX = append(p.MX, v)
		case "max_age":
			p.MaxAge = v
		}
	}
	if !versionOK {
		return MTASTSPolicy{}, false
	}
	return p, true
}
