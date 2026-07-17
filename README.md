# mailgrade

Grade any domain's email deliverability from your terminal. `mailgrade` checks
the DNS records and mail-server settings that decide whether your email reaches
the inbox (SPF, DKIM, DMARC, reverse DNS, STARTTLS, MTA-STS, TLS-RPT, DANE, BIMI,
and blocklists), then prints a 0-100 score, an A-F grade, and the exact record to
publish for each gap.

One command, one static binary, no dependencies. It reads a domain's public DNS
and SMTP posture and never sends mail.

```
mailgrade example.com
```

```
  example.com    B    83/100

  ✓  MX           2 MX host(s): mx1.example.com (pref 10), mx2.example.com (pref 20)
  ✓  SPF          v=spf1 with -all (hard fail)
  ✓  DKIM         selector "google" found
  ⚠  DMARC        p=none
  ✓  PTR / rDNS   all 2 MX address(es) have forward-confirmed rDNS
  ✓  STARTTLS     mx1.example.com offers STARTTLS
  ⚠  MTA-STS      no MTA-STS policy
  ⚠  TLS-RPT      no TLS-RPT record
  ─  DANE         no TLSA records (DANE is optional)
  ─  BIMI         no BIMI record (optional)
  ✓  Blocklists   not listed (8 of 8 zone lookups answered)

  Fixes
    ⚠ DMARC: Once your reports look clean, move to p=quarantine and then p=reject.
    ⚠ MTA-STS: Publish an _mta-sts TXT record and serve a policy to require TLS.
    ⚠ TLS-RPT: Publish _smtp._tls TXT "v=TLSRPTv1; rua=..." to receive TLS failure reports.
```

## Install

```
curl -fsSL https://raw.githubusercontent.com/aloki-alok/mailgrade/main/install.sh | sh
```

or with Go:

```
go install github.com/aloki-alok/mailgrade@latest
```

Prebuilt binaries for Linux, macOS, and Windows are on the
[releases](https://github.com/aloki-alok/mailgrade/releases) page.

## Usage

```
mailgrade <domain> [flags]
```

The argument can be a bare domain, a URL, or an email address; mailgrade reduces
it to the domain to scan.

```
mailgrade example.com
mailgrade https://example.com
mailgrade you@example.com --selector google -V
mailgrade example.com --json --fail-on warn
```

| flag | meaning |
|------|---------|
| `--selector NAME` | also probe this DKIM selector |
| `--ip ADDR` | also check this sending IP for reverse DNS and blocklists (repeatable) |
| `--resolver ADDR` | use this nameserver instead of the system resolver |
| `--timeout DUR` | per-lookup timeout (default 5s) |
| `--no-network` | skip checks that open TCP connections (MX reachability, STARTTLS) |
| `--verbose`, `-V` | show each check's detail lines |
| `--json` | emit the report as JSON |
| `--fail-on LEVEL` | exit non-zero if any check is at least `warn` or `fail` |

## In CI

`--fail-on` turns mailgrade into a gate, so a regression in your domain's mail
setup breaks the build:

```yaml
- run: mailgrade example.com --fail-on warn
```

## What it checks

| check | what it looks at |
|-------|------------------|
| MX | mail exchangers resolve and are reachable (null MX is recognized) |
| SPF | one `v=spf1` record, its `all` qualifier, and the ten-lookup limit |
| DKIM | a working selector under `_domainkey`, key size, and revocation |
| DMARC | the `_dmarc` policy, subdomain policy, percentage, and reporting address |
| PTR / rDNS | each MX IP has forward-confirmed reverse DNS |
| STARTTLS | the MX offers STARTTLS and presents a valid, unexpired certificate |
| MTA-STS | the `_mta-sts` record and served policy, and its mode |
| TLS-RPT | an SMTP TLS reporting policy |
| DANE | `_25._tcp` TLSA records on the MX |
| BIMI | a `default._bimi` logo record |
| Blocklists | sending IPs against well-known DNS blocklists |

Run `mailgrade` with no domain to see the full help.

## Notes

- **DKIM selectors cannot be listed from DNS.** mailgrade probes common selector
  names; if your domain uses a custom one, pass `--selector <name>`.
- **STARTTLS needs outbound port 25.** Many networks block it; when the MX cannot
  be reached the check is skipped, never counted against the domain.
- **Blocklist queries can be rate-limited** on shared public resolvers. Pass
  `--resolver` with a private or dedicated nameserver for a reliable answer.
- A grade reflects the records mailgrade can see, not a guarantee of delivery.
  Use it to find and fix gaps, not as a certificate.

## License

MIT
