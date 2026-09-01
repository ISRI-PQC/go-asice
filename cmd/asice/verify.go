// verify subcommand: the verify flow over asic.Verify + the
// human-readable report.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/isri-pqc/asice/asic"
	asiccrypto "github.com/isri-pqc/asice/asic/crypto"
	xcrypto "github.com/isri-pqc/xmlsig/crypto"
)

// verifyInput is the parsed verify request (testable without a
// command).
type verifyInput struct {
	path           string
	roots          string
	intermediates  string
	tstSigners     string
	ocspResponders string
	profile        string
}

// runVerifyCmd validates verifyInput, runs asic.Verify, and prints
// the report to stdout. A *usageErr is a usage error (exit 2); any
// other error is a verification failure (exit 1).
func runVerifyCmd(stdout io.Writer, in verifyInput) error {
	if in.path == "" {
		return &usageErr{msg: "a container path is required"}
	}
	if in.roots == "" {
		return &usageErr{msg: "--roots is required (trust anchor certificates)"}
	}

	var prof asic.Profile
	in.profile = strings.ToLower(strings.TrimSpace(in.profile))
	switch in.profile {
	case "bes", "":
		prof = asic.ProfileBES
	case "ts":
		prof = asic.ProfileTS
	default:
		return &usageErr{msg: fmt.Sprintf("unknown --profile %q (want bes or ts)", in.profile)}
	}

	rootsPEM, err := os.ReadFile(in.roots)
	if err != nil {
		return fmt.Errorf("read --roots: %w", err)
	}
	var interPEM, tstSignersPEM, ocspRespondersPEM []byte
	if in.intermediates != "" {
		interPEM, err = os.ReadFile(in.intermediates)
		if err != nil {
			return fmt.Errorf("read --intermediates: %w", err)
		}
	}
	if in.tstSigners != "" {
		tstSignersPEM, err = os.ReadFile(in.tstSigners)
		if err != nil {
			return fmt.Errorf("read --tst-signers: %w", err)
		}
	}
	if in.ocspResponders != "" {
		ocspRespondersPEM, err = os.ReadFile(in.ocspResponders)
		if err != nil {
			return fmt.Errorf("read --ocsp-responders: %w", err)
		}
	}
	if prof == asic.ProfileTS && len(tstSignersPEM) == 0 {
		return &usageErr{msg: "--tst-signers is required for the ts profile"}
	}

	// The standard crypto modules are the default implementations
	// (ADR 0004). The standard TST verifier carries the TSA signer
	// pool (--tst-signers) and the intermediate pool as its trust
	// boundary.
	tstSigners, err := asic.ParsePEMCerts(tstSignersPEM)
	if err != nil {
		return fmt.Errorf("parse --tst-signers: %w", err)
	}
	intermediates, err := asic.ParsePEMCerts(interPEM)
	if err != nil {
		return fmt.Errorf("parse --intermediates: %w", err)
	}
	rep, err := asic.Verify(in.path, asic.VerifyOptions{
		Profile:           prof,
		RootsPEM:          rootsPEM,
		IntermediatesPEM:  interPEM,
		OCSPRespondersPEM: ocspRespondersPEM,
		DigestModule:      xcrypto.NewStdXMLDigestModule(),
		VerifierModule:    asiccrypto.NewStdVerifierModule(),
		ChainModule:       asiccrypto.NewStdCertificateChainModule(),
		OCSPModule:        asiccrypto.NewStdOCSPVerifierModule(),
		TSTVerifier:       asiccrypto.NewStdTSTVerifierModule(tstSigners, intermediates),
	})
	if err != nil {
		return err
	}

	printReport(stdout, in.path, rep)
	if !rep.OK {
		return errors.New("verification failed")
	}
	return nil
}

// printReport renders the human-readable verdict.
func printReport(w io.Writer, path string, rep *asic.Report) {
	fmt.Fprintf(w, "container: %s\n", path)
	fmt.Fprintf(w, "profile:   %s\n", profileName(rep.Profile))
	if len(rep.Errors) > 0 {
		fmt.Fprintln(w, "structure:")
		for _, e := range rep.Errors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
		fmt.Fprintln(w, "result:    FAILED")
		return
	}
	if len(rep.DataFiles) > 0 {
		fmt.Fprintf(w, "files:     %s\n", strings.Join(rep.DataFiles, ", "))
	}
	fmt.Fprintln(w, "signatures:")
	for _, s := range rep.Signatures {
		status := "ok"
		if !s.OK {
			status = "FAILED"
		}
		line := fmt.Sprintf("  %s: %s  signer=%q", s.ID, status, s.Signer)
		if !s.SigningTime.IsZero() {
			line += fmt.Sprintf("  signingTime=%s", s.SigningTime.Format(time.RFC3339))
		}
		fmt.Fprintln(w, line)
		for _, e := range s.Errors {
			fmt.Fprintf(w, "      - %s\n", e)
		}
	}
	fmt.Fprintf(w, "result:    %s\n", verdict(rep.OK))
}

func profileName(p asic.Profile) string {
	switch p {
	case asic.ProfileTS:
		return "ts"
	default:
		return "bes"
	}
}

func verdict(ok bool) string {
	if ok {
		return "OK"
	}
	return "FAILED"
}
