// Package cli parses mailgrade's arguments and runs a scan. The default command
// grades a domain; `version` prints the build version.
package cli

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aloki-alok/mailgrade/internal/checks"
	"github.com/aloki-alok/mailgrade/internal/report"
	"github.com/aloki-alok/mailgrade/internal/ui"
)

// Version is set at build time via -ldflags; resolveVersion falls back to the
// module's build info for `go install` builds.
var Version = "dev"

// Run is the entry point. It returns the process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println("mailgrade " + resolveVersion())
		return 0
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	}
	return scan(args)
}

type flags struct {
	domain  string
	opts    checks.Options
	jsonOut bool
	verbose bool
	failOn  checks.Status
	hasFail bool
}

func scan(args []string) int {
	f, err := parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mailgrade: %v\n", err)
		return 2
	}

	rep := checks.Run(f.domain, f.opts)

	if f.jsonOut {
		if err := report.JSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "mailgrade: %v\n", err)
			return 1
		}
	} else {
		report.Terminal(os.Stdout, rep, ui.For(os.Stdout), f.verbose)
	}

	if f.hasFail && worstStatus(rep) >= f.failOn {
		return 1
	}
	return 0
}

// worstStatus returns the most severe penalized status in a report (Fail > Warn),
// ignoring NA and Skip so the runner's network never trips the CI gate.
func worstStatus(r checks.Report) checks.Status {
	worst := checks.Pass
	for _, res := range r.Results {
		if res.Status == checks.NA || res.Status == checks.Skip {
			continue
		}
		if res.Status > worst && (res.Status == checks.Warn || res.Status == checks.Fail) {
			worst = res.Status
		}
	}
	return worst
}

func parse(args []string) (flags, error) {
	f := flags{opts: checks.Options{Timeout: 5 * time.Second}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			f.jsonOut = true
		case a == "--verbose" || a == "-V":
			f.verbose = true
		case a == "--no-network":
			f.opts.SkipNetwork = true
		case a == "--resolver":
			v, err := next(args, &i, a)
			if err != nil {
				return f, err
			}
			f.opts.Resolver = v
		case a == "--selector":
			v, err := next(args, &i, a)
			if err != nil {
				return f, err
			}
			f.opts.Selector = v
		case a == "--ip":
			v, err := next(args, &i, a)
			if err != nil {
				return f, err
			}
			f.opts.SendingIPs = append(f.opts.SendingIPs, v)
		case a == "--timeout":
			v, err := next(args, &i, a)
			if err != nil {
				return f, err
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return f, fmt.Errorf("bad --timeout %q: %w", v, err)
			}
			f.opts.Timeout = d
		case a == "--fail-on":
			v, err := next(args, &i, a)
			if err != nil {
				return f, err
			}
			st, err := parseStatus(v)
			if err != nil {
				return f, err
			}
			f.failOn, f.hasFail = st, true
		case strings.HasPrefix(a, "-"):
			return f, fmt.Errorf("unknown flag %q", a)
		default:
			if f.domain != "" {
				return f, fmt.Errorf("unexpected argument %q (domain already set to %q)", a, f.domain)
			}
			f.domain = normalizeDomain(a)
		}
	}
	if f.domain == "" {
		return f, fmt.Errorf("no domain given")
	}
	return f, nil
}

// normalizeDomain accepts a bare domain, a URL, or an email address and reduces
// it to the domain to scan.
func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(strings.SplitN(s, "/", 2)[0], ".")
	return strings.ToLower(s)
}

func next(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s needs a value", flag)
	}
	*i++
	return args[*i], nil
}

func parseStatus(s string) (checks.Status, error) {
	switch strings.ToLower(s) {
	case "warn":
		return checks.Warn, nil
	case "fail":
		return checks.Fail, nil
	default:
		return checks.Pass, fmt.Errorf("bad --fail-on %q (want warn or fail)", s)
	}
}

func resolveVersion() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return Version
}

func usage(w *os.File) {
	fmt.Fprint(w, `mailgrade: grade a domain's email deliverability posture from your terminal.

Usage:
  mailgrade <domain> [flags]
  mailgrade version

It checks MX, SPF, DKIM, DMARC, reverse DNS, STARTTLS, MTA-STS, TLS-RPT, DANE,
BIMI, and blocklists, then prints a 0-100 score, an A-F grade, and the record to
publish for each gap. It reads public DNS and SMTP posture and never sends mail.

Flags:
  --selector NAME    also probe this DKIM selector
  --ip ADDR          also check this sending IP for rDNS and blocklists (repeatable)
  --resolver ADDR    use this nameserver instead of the system resolver
  --timeout DUR      per-lookup timeout (default 5s)
  --no-network       skip checks that open TCP connections (MX reachability, STARTTLS)
  --verbose, -V      show each check's detail lines
  --json             emit the report as JSON
  --fail-on LEVEL    exit non-zero if any check is at least LEVEL (warn|fail)

Examples:
  mailgrade example.com
  mailgrade example.com --selector google -V
  mailgrade example.com --json --fail-on warn
`)
}
