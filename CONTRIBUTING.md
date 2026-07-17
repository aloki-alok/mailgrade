# Contributing to mailgrade

Thanks for helping out. mailgrade is a single Go binary (the `mg` command); the
loop is small.

## Build and test

```
go build ./...
go test ./...
go vet ./...
```

`go run ./cmd/mg <domain>` runs your working copy against a real domain:

```
go run ./cmd/mg example.com
go run ./cmd/mg example.com --json
```

## Layout

- `internal/dns` resolves records (and DNS-over-HTTPS for TLSA).
- `internal/records` parses SPF, DMARC, DKIM, and MTA-STS as pure, tested
  functions.
- `internal/checks` runs one check per file and scores the result.
- `internal/report` renders the terminal and JSON output.
- `internal/cli` holds flag parsing and the command surface.
- `DESIGN.md` is the why: the problem, the non-goals, and the shape. Read it
  before a large change so a feature lands where it belongs.

## Adding a check or a provider

A new check is a file under `internal/checks` returning a `Result`, added to the
list in `checks.go`; keep parsing logic in `internal/records` so it is testable
without DNS. To teach mailgrade a new mail provider for DKIM detection, add an
entry to `providers` in `internal/checks/providers.go`.

## Pull requests

- Keep each PR to one concern, with a clear title that says the intent.
- Add a test for behavior you change, especially in `internal/records` where a
  wrong parse would misreport a domain.
- `go test ./...` and `go vet ./...` must pass. CI runs both on every PR.
- Match the surrounding style. No new dependency without a reason in the PR.

## Reporting bugs

Open an issue with the version (`mg version`), the domain (or a minimal
reproduction), and the output you got versus what you expected.
