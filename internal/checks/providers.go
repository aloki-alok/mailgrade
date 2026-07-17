package checks

import (
	"strings"

	"github.com/aloki-alok/mailgrade/internal/dns"
)

// provider maps an email provider to how mailgrade recognizes and helps with it:
// a token that appears in an SPF include, the DKIM selectors it commonly uses,
// and a human name used in fixes. Recognizing the provider from SPF lets the
// DKIM check probe the right selectors first and name the provider in its
// advice, instead of blindly guessing.
type provider struct {
	name      string
	spfToken  string
	selectors []string
	dkimHint  string
}

var providers = []provider{
	{
		name: "Google Workspace", spfToken: "_spf.google.com",
		selectors: []string{"google"},
		dkimHint:  "Turn on DKIM in the Google Admin console (Apps > Google Workspace > Gmail > Authenticate email) and publish the google._domainkey record it gives you.",
	},
	{
		name: "Microsoft 365", spfToken: "spf.protection.outlook.com",
		selectors: []string{"selector1", "selector2"},
		dkimHint:  "Enable DKIM in the Microsoft 365 Defender portal and publish the selector1/selector2 CNAME records it provides.",
	},
	{
		name: "SendGrid", spfToken: "sendgrid.net",
		selectors: []string{"s1", "s2"},
		dkimHint:  "Complete SendGrid domain authentication and publish the s1/s2 CNAME records it generates.",
	},
	{
		name: "Amazon SES", spfToken: "amazonses.com",
		selectors: []string{"selector1", "selector2"},
		dkimHint:  "Enable Easy DKIM for the domain in Amazon SES and publish the three CNAME records it lists.",
	},
	{
		name: "Mailgun", spfToken: "mailgun.org",
		selectors: []string{"mx", "smtp", "k1", "mg"},
		dkimHint:  "Add the domain in Mailgun and publish the DKIM (mx._domainkey / k1) TXT record it shows.",
	},
	{
		name: "Mailchimp / Mandrill", spfToken: "servers.mcsv.net",
		selectors: []string{"k1", "k2", "k3", "mandrill"},
		dkimHint:  "Verify the domain in Mailchimp/Mandrill and publish the k1/k2/k3 CNAME records.",
	},
	{
		name: "Zoho Mail", spfToken: "zoho.",
		selectors: []string{"zoho", "zmail", "1522905800826"},
		dkimHint:  "Enable DKIM in the Zoho Mail admin console and publish the selector TXT record it provides.",
	},
	{
		name: "Postmark", spfToken: "spf.mtasv.net",
		selectors: []string{"pm", "pm1", "pm2"},
		dkimHint:  "Verify the domain in Postmark and publish the DKIM TXT record it lists.",
	},
	{
		name: "Zendesk", spfToken: "mail.zendesk.com",
		selectors: []string{"zendesk1", "zendesk2"},
		dkimHint:  "Enable DKIM for the domain in Zendesk and publish the zendesk1/zendesk2 CNAME records.",
	},
	{
		name: "Fastmail", spfToken: "spf.messagingengine.com",
		selectors: []string{"fm1", "fm2", "fm3"},
		dkimHint:  "Fastmail sets DKIM up automatically; publish the fm1/fm2/fm3 CNAME records shown under Settings > Domains.",
	},
	{
		name: "Migadu", spfToken: "spf.migadu.com",
		selectors: []string{"key1", "key2", "key3"},
		dkimHint:  "Publish the key1/key2/key3 CNAME records from the Migadu admin panel's DNS instructions.",
	},
	{
		name: "iCloud Mail", spfToken: "include:icloud.com",
		selectors: []string{"sig1"},
		dkimHint:  "Publish the sig1._domainkey CNAME record shown in iCloud settings when you add the custom domain.",
	},
	{
		name: "Proton Mail", spfToken: "_spf.protonmail.ch",
		selectors: []string{"protonmail", "protonmail2", "protonmail3"},
		dkimHint:  "Enable the custom domain in Proton Mail and publish the three protonmail._domainkey CNAME records.",
	},
}

// mxTokens maps a substring of an MX hostname to the provider's SPF include, so
// the SPF fix can suggest the right include even when the domain has no SPF
// record to read.
var mxTokens = map[string]string{
	"outlook.com":  "spf.protection.outlook.com",
	"google.com":   "_spf.google.com",
	"googlemail":   "_spf.google.com",
	"zoho":         "zoho.com",
	"pphosted.com": "spf.protection.outlook.com",
}

// detectProvider returns the first provider whose SPF token appears anywhere in
// the SPF record text (which includes its include: targets), or nil.
func detectProvider(spf string) *provider {
	lower := strings.ToLower(spf)
	for i := range providers {
		if strings.Contains(lower, providers[i].spfToken) {
			return &providers[i]
		}
	}
	return nil
}

// providerFromMX finds the provider suggested by the MX hostnames, used to make
// the SPF fix concrete when there is no SPF record to inspect.
func providerFromMX(mx []dns.MXHost) *provider {
	for _, m := range mx {
		host := strings.ToLower(m.Host)
		for token, spfToken := range mxTokens {
			if strings.Contains(host, token) {
				if p := detectProvider(spfToken); p != nil {
					return p
				}
			}
		}
	}
	return nil
}
