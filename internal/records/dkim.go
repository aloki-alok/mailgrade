package records

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
)

// DKIM is a parsed DKIM public-key record found at <selector>._domainkey.<domain>.
type DKIM struct {
	Raw string
	// KeyType is the k= tag ("rsa" by default, or "ed25519").
	KeyType string
	// PublicKey is the base64 p= tag. An empty p= means the key was revoked.
	PublicKey string
	// Revoked is true when p= is present but empty (the key has been withdrawn).
	Revoked bool
	// Testing is true when the t=y flag is set (the domain is testing DKIM).
	Testing bool
	// Bits is the key size in bits when it can be determined from the key, else 0.
	Bits int
	Tags map[string]string
}

// ParseDKIM parses a DKIM record. It returns ok=false only when the text has no
// p= tag at all, since a DKIM record is otherwise identified by living at a
// _domainkey name (some publishers omit the v=DKIM1 tag).
func ParseDKIM(txt string) (DKIM, bool) {
	tags := parseTags(txt)
	p, hasP := tags["p"]
	if !hasP {
		return DKIM{}, false
	}
	d := DKIM{
		Raw:       txt,
		KeyType:   strings.ToLower(orDefault(tags["k"], "rsa")),
		PublicKey: p,
		Revoked:   strings.TrimSpace(p) == "",
		Testing:   strings.Contains(strings.ToLower(tags["t"]), "y"),
		Tags:      tags,
	}
	d.Bits = keyBits(d.KeyType, p)
	return d, true
}

// keyBits decodes a DKIM public key and returns its size in bits, or 0 when it
// cannot be parsed. An undersized RSA key (under 1024 bits) is a real weakness.
func keyBits(keyType, b64 string) int {
	if strings.TrimSpace(b64) == "" {
		return 0
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return 0
	}
	if keyType == "ed25519" {
		if len(der) == ed25519.PublicKeySize {
			return 256
		}
		return 0
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return 0
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
