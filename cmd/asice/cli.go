// cli.go: the cobra command tree, wired through fang, and the exit
// code mapping (0 ok, 1 create/verify failure, 2 usage error).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

// usageErr marks a usage error; the CLI maps it to exit 2.
type usageErr struct{ msg string }

func (e *usageErr) Error() string { return e.msg }

// opError marks an operational create/verify failure; the CLI maps it
// to exit 1.
type opError struct{ err error }

func (e *opError) Error() string { return e.err.Error() }
func (e *opError) Unwrap() error { return e.err }

// execute builds the command tree, runs it through fang (which prints
// help and errors), and maps the result to the CLI exit code.
func execute(stdout, stderr io.Writer, args []string) int {
	root := newRootCommand()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err := fang.Execute(context.Background(), root,
		fang.WithVersion(appVersion),
		fang.WithErrorHandler(plainErrorHandler),
	)
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if isUsageError(err) {
		return exitUsageErr
	}
	return exitFailed
}

// plainErrorHandler renders errors as deterministic plain text so the
// real message always reaches stderr (TTY or captured output).
func plainErrorHandler(w io.Writer, _ fang.Styles, err error) {
	fmt.Fprintf(w, "asice: %v\n\nRun 'asice --help' for usage.\n", err)
}

// isUsageError reports whether err is a usage error: a *usageErr (flag
// parse or input validation) or cobra's "unknown command" error.
func isUsageError(err error) bool {
	if err == nil {
		return false
	}
	var ue *usageErr
	if errors.As(err, &ue) {
		return true
	}
	return strings.HasPrefix(err.Error(), "unknown command")
}

// newRootCommand is the asice root command: create + verify subcommands
// plus the fang freebies (--version, completion, man).
func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "asice",
		Short: "create and verify ASiC-E containers (XAdES XML form)",
		Long: `asice creates and verifies ASiC-E containers (XAdES XML form, TS 102 918 / BDOC 2.1.2 shape) in the BES and TS profiles.

Exit codes: 0 ok; 1 create/verify failure; 2 usage error.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bare invocation: print the help, then a usage error
			// (exit 2).
			if len(args) > 0 {
				return &usageErr{msg: fmt.Sprintf("unknown command %q", args[0])}
			}
			if err := cmd.Help(); err != nil {
				return err
			}
			return &usageErr{msg: `try "asice --help"`}
		},
	}
	// Route flag parse errors through the usage-error type so they
	// map to exit 2.
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &usageErr{msg: err.Error()}
	})
	root.AddCommand(newCreateCommand(), newVerifyCommand())
	return root
}

// newCreateCommand is the create subcommand (flag parsing + dispatch
// to runCreateCmd).
func newCreateCommand() *cobra.Command {
	var in createInput
	var signingTime string
	cmd := &cobra.Command{
		Use:   "create DOC [DOC...]",
		Short: "sign one or more documents into an ASiC-E container",
		Long: `sign one or more documents into an ASiC-E container.

The documents to add are the positional arguments DOC (file paths),
for example:

  asice create -o out.asice --cert signer.pem report.pdf appendix.pdf

Flags may be placed before or after the document paths.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			st := time.Now().UTC()
			if signingTime != "" {
				parsed, err := time.Parse(time.RFC3339, signingTime)
				if err != nil {
					return &usageErr{msg: fmt.Sprintf("--signing-time must be RFC 3339: %v", err)}
				}
				st = parsed
			}
			in.signingTime = st
			in.docs = args
			err := runCreateCmd(cmd.Context(), cmd.ErrOrStderr(), in)
			if isUsageError(err) {
				return err
			}
			if err != nil {
				return &opError{err: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&in.out, "o", "o", "", "output container path (required)")
	cmd.Flags().StringVar(&in.certFile, "cert", "", "signer file: PEM with one CERTIFICATE block and one private key block (required)")
	cmd.Flags().StringVar(&in.profile, "profile", "bes", "signature profile: bes or ts")
	cmd.Flags().StringVar(&in.chainFile, "chain", "", "ts profile: PEM with exactly two certificates (OCSP responder, then CA)")
	cmd.Flags().StringVar(&in.ocspFile, "ocsp-file", "", "ts profile: DER basic OCSP response for the signer")
	cmd.Flags().StringVar(&in.tstURL, "tst", "", "ts profile: RFC 3161 TSA endpoint URL")
	cmd.Flags().StringVar(&in.tstSigners, "tst-signers", "", "ts profile: PEM with the TSA signing certificate(s)")
	cmd.Flags().StringVar(&signingTime, "signing-time", "", "RFC 3339 signing time (default: now, UTC)")
	return cmd
}

// newVerifyCommand is the verify subcommand (flag parsing + dispatch
// to runVerifyCmd).
func newVerifyCommand() *cobra.Command {
	var in verifyInput
	cmd := &cobra.Command{
		Use:   "verify CONTAINER",
		Short: "verify a container and print a human-readable report",
		Long: `verify an ASiC-E container and print a human-readable report.

The container to verify is the positional argument CONTAINER, for
example:

  asice verify out.asice --roots roots.pem --profile bes`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &usageErr{msg: "a container path is required"}
			}
			if len(args) > 1 {
				return &usageErr{msg: fmt.Sprintf("expected exactly one container path, got %d", len(args))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			in.path = args[0]
			err := runVerifyCmd(cmd.OutOrStdout(), in)
			if isUsageError(err) {
				return err
			}
			if err != nil {
				return &opError{err: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&in.roots, "roots", "", "PEM with the trust anchor certificate(s) (required)")
	cmd.Flags().StringVar(&in.intermediates, "intermediates", "", "PEM with intermediate CA certificate(s)")
	cmd.Flags().StringVar(&in.tstSigners, "tst-signers", "", "ts profile: PEM with the TSA signing certificate(s) (required)")
	cmd.Flags().StringVar(&in.ocspResponders, "ocsp-responders", "", "ts profile: PEM with the configured OCSP responder certificate(s)")
	cmd.Flags().StringVar(&in.profile, "profile", "bes", "verification profile: bes or ts")
	return cmd
}
