# mailgrade: design

`mailgrade` grades a domain's email deliverability posture from the terminal. It
looks up everything a receiving mail server checks before it trusts your mail
(authentication, transport security, reputation) and reports a 0-100 score, an
A-F grade, and the exact record to add for each gap.

```
mailgrade example.com
```

Single static binary, no runtime dependencies, color that switches off when
piped. It reads the public, over-the-wire posture of a domain: DNS records and
what its mail servers present. It does not read your server config and does not
send mail.

## 1. Problem

Getting email delivered to the inbox depends on a stack of DNS records and TLS
settings that are easy to get subtly wrong and painful to debug: SPF that
exceeds its ten-lookup limit, DMARC stuck on `p=none`, a missing DKIM selector,
reverse DNS that does not match, no MTA-STS policy, an expired SMTP certificate.
Each is invisible until mail starts landing in spam.

The tools that check these are mostly web dashboards you paste a domain into one
field at a time. There is no fast, scriptable, single-command way to see a
domain's whole mail posture and what to fix, from a terminal or from CI.

For whom: anyone who runs a sending domain, developers wiring up transactional
email, and sysadmins maintaining mail servers.

## 2. Non-goals

- **Not a mail sender / seed test.** It does not send a message and measure
  inbox placement the way a seed-list test does. It checks configuration, not
  delivery of a specific message.
- **Not a server-config linter.** It does not read Postfix, Exim, or Dovecot
  files. It checks the public posture over DNS and SMTP, black-box, so it works
  against any domain without access to its hosts.
- **Not a content / spam-score checker.** No message body, no keyword scoring.
- **Not a continuous monitor** (though `--json` makes it easy to run on a
  schedule and diff).
- **Not a certificate authority or reputation database.** It reports what it
  observes; it does not rank domains against each other.

## 3. Alternatives considered and rejected

1. **A hosted web checker.** Rejected: the whole point is a scriptable local
   command that fits in CI and a terminal. Web tools cannot.
2. **Wrap `dig`, `openssl`, and shell.** Rejected: brittle parsing, no scoring,
   no portability. A single typed binary that parses records itself is testable
   and ships anywhere.
3. **Pull in a full DNS library.** Rejected for the common path: the standard
   library resolves MX, TXT, A, and PTR reliably and keeps the binary
   dependency-free. The one record type it cannot do (TLSA, for DANE) is fetched
   over DNS-over-HTTPS as a best-effort extra, so DANE never becomes a hard
   dependency on a third-party library.
4. **Only check the SPF/DKIM/DMARC trio.** Rejected: transport security
   (MTA-STS, TLS-RPT, DANE, STARTTLS) and reverse DNS are real deliverability
   factors. Half a picture misleads.

## 4. Chosen approach

```
  domain
    │
    ▼
  ┌──────────────┐   stdlib resolver (MX/TXT/A/PTR), custom via --resolver;
  │  dns + net   │   DoH best-effort for TLSA; SMTP dial for STARTTLS + cert.
  └──────┬───────┘
    │  raw records + connection facts
    ▼
  ┌──────────────┐   each check parses its records and returns a Result
  │   checks      │   {name, status (pass/warn/fail/na/skip), findings, fixes}.
  └──────┬───────┘   parsers are pure and table-tested.
    │  []Result
    ▼
  ┌──────────────┐   score = 100 − Σ weighted penalties; grade A-F.
  │   report      │   terminal (color off when piped) | --json.
  └──────┬───────┘   exit code from --fail-on for CI.
    ▼
   stdout + exit code
```

Checks (v0.1):

| check | weight | looks at |
|-------|--------|----------|
| MX | core | MX records resolve and hosts are reachable |
| SPF | core | one `v=spf1` TXT, the `all` qualifier, and the ≤10 DNS-lookup limit |
| DKIM | core | at least one working selector under `_domainkey`, key size, not revoked |
| DMARC | core | `_dmarc` policy, `p=`/`sp=`, `pct`, and a reporting address |
| PTR / rDNS | core | each MX IP has reverse DNS that forward-confirms |
| STARTTLS | high | MX offers STARTTLS and presents a valid, unexpired, matching cert |
| MTA-STS | bonus | `_mta-sts` TXT plus a served policy, and its mode |
| TLS-RPT | bonus | `_smtp._tls` reporting record |
| DANE | bonus | `_25._tcp` TLSA records on the MX |
| BIMI | bonus | `default._bimi` logo record (and VMC) |
| DNSBL | signal | sending IPs against well-known blocklists |

Statuses: `pass`, `warn` (works but weak, e.g. DMARC `p=none`), `fail`
(missing/broken and it matters), `na` (legitimately not applicable, e.g. a
parked domain with no MX), `skip` (could not test, e.g. port 25 blocked on the
runner). Only `warn` and `fail` cost score; `skip` never penalizes a domain for
the runner's network.

Grade: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F.

## 5. Tradeoffs

- **Resolver view, not authoritative.** Results reflect what a resolver returns,
  which is what real senders/receivers see, but can lag a just-changed record by
  its TTL. `--resolver` pins a specific server for reproducibility.
- **Port 25 may be blocked** on the machine running it (many clouds block
  outbound 25). The STARTTLS check degrades to `skip` with a clear note rather
  than failing the domain.
- **Heuristics on DKIM selector discovery.** DKIM has no way to enumerate
  selectors from DNS, so discovery probes a list of common selector names and
  accepts a user-supplied `--selector`. A domain using an exotic selector we do
  not probe shows as "no selector found (try --selector)", never a false
  "broken".

## 6. Success and failure metrics

- **Success:** on a well-configured domain it reports A with the strong records
  recognized; on a domain with a known gap (e.g. `p=none`, no MTA-STS) it names
  that specific gap with the record to publish. Parsers are covered by tests
  against real-world record strings.
- **Failure signal:** a false `fail` on a correctly configured domain (erodes
  trust), or a green grade on a domain that is actually misconfigured.

## 7. Rollout

Public repository, MIT. Released as prebuilt binaries and `go install`, with a
one-line install script. Semver tags; a tag builds and publishes the release.

## 8. Rollback

A read-only CLI with no stored state and no service. Rollback is installing an
earlier version or removing the binary. Running it changes nothing on any domain
it inspects.

## 9. Monitoring + runbook

Not a service. The reference is the README and `mailgrade` self-documenting
help. Repository CI (build, vet, test) is the health signal.

## Deviations

(Appended during implementation as "changed X because Y".)
