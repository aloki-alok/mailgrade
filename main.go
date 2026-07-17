// Command mailgrade grades a domain's email deliverability posture (SPF, DKIM,
// DMARC, transport security, and reputation) from the terminal, with a 0-100
// score, an A-F grade, and the record to publish for each gap.
package main

import (
	"os"

	"github.com/aloki-alok/mailgrade/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
