// Command asice creates and verifies ASiC-E containers (XAdES XML
// form, TS 102 918 / BDOC 2.1.2 shape).
package main

import (
	"os"
)

// appVersion is reported by `asice --version` (fang.WithVersion).
const appVersion = "0.2.0"

// Exit codes: 0 ok, 1 create/verify failure, 2 usage error.
const (
	exitOK       = 0
	exitFailed   = 1
	exitUsageErr = 2
)

func main() {
	os.Exit(execute(os.Stdout, os.Stderr, os.Args[1:]))
}
