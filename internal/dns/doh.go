package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// TLSA queries TLSA records (DANE) for name over DNS-over-HTTPS, since the
// standard resolver cannot request type 52. It is best-effort: any error means
// "could not determine", never a hard failure, so DANE stays an optional bonus
// and never depends on the DoH provider being reachable.
func (r *Resolver) TLSA(name string) ([]string, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", "TLSA")
	endpoint := "https://cloudflare-dns.com/dns-query?" + q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: r.timeout + time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	var body struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range body.Answer {
		if a.Type == 52 { // TLSA
			out = append(out, a.Data)
		}
	}
	return out, nil
}
