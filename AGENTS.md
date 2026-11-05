# AGENTS.md

mailgrade is a Go CLI (`mg`) that grades a domain's email deliverability from public DNS and SMTP. It ships as one static binary with no dependencies, and it never sends mail.

## Commands

- Build: `go build ./...`
- Test: `go test ./...`
- Lint: `go vet ./...`
- Run on a real domain: `go run ./cmd/mg example.com` (add `--json` for the JSON report)
- Help: `go run ./cmd/mg --help`

## Layout

- `cmd/mg/main.go`: entry point, calls `cli.Run`.
- `internal/cli`: flag parsing and the command surface.
- `internal/dns`: DNS lookups, plus DNS-over-HTTPS for TLSA.
- `internal/records`: pure parsers for SPF, DMARC, DKIM and MTA-STS records.
- `internal/checks`: one check per file (`check_*.go`), scoring in `checks.go` and `verdict.go`, DKIM provider table in `providers.go`.
- `internal/report`: terminal and JSON output.
- `internal/ui`: color and symbols.
- `DESIGN.md`: the problem, non-goals and shape. Read it before a large change.
- `docs/index.html`: the landing page for GitHub Pages.

## Rules

- The command is `mg`, not `mailgrade`. Keep the binary name in docs and code.
- The tool is read-only. It must never send mail or change DNS.
- No new dependency without a reason in the PR. The binary stays static.
- Keep parsing in `internal/records` as pure functions, so a test runs without DNS.
- A new check is a file in `internal/checks` that returns a `Result`. Add it to the list in `checks.go`.
- A new mail provider for DKIM detection is one entry in `providers` in `internal/checks/providers.go`.
- A wrong parse misreports a domain. Add a test for every parsing change.
- STARTTLS needs outbound port 25. When the MX is unreachable the check is skipped, never counted against the domain.
- Color switches off when output is piped. Do not break that.

## Before you open a PR

CI (`.github/workflows/ci.yml`) runs these on every PR:

1. `go vet ./...`
2. `go test ./...`
3. `go build ./...`

Keep each PR to one concern, with a title that says the intent.
