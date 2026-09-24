// ocsp subcommand: the ocsp fetch flow over the ocsp package (fresh
// stored OCSP response for the signer certificate).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"crypto/x509"

	"github.com/isri-pqc/go-asice/asic"
	"github.com/isri-pqc/go-asice/ocsp"
	"github.com/spf13/cobra"
)

// ocspFetchInput is the parsed ocsp fetch request (testable without a
// command).
type ocspFetchInput struct {
	cert    string
	out     string
	issuer  string
	chain   string
	url     string
	timeout time.Duration
}

// newOCSPCommand is the ocsp parent command (the fetch subcommand).
func newOCSPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ocsp",
		Short: "OCSP responder operations",
	}
	cmd.AddCommand(newOCSPFetchCommand())
	return cmd
}

// newOCSPFetchCommand is the ocsp fetch subcommand (flag parsing +
// dispatch to runOCSPFetchCmd).
func newOCSPFetchCommand() *cobra.Command {
	var in ocspFetchInput
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "fetch a fresh stored OCSP response for a signer certificate",
		Long: `fetch a fresh stored OCSP response for the signer certificate.

The ASiC-E TS profile stores the OCSP response in the container (the
offline certificate-status attestation). This command builds the RFC
6960 request from the signer certificate and writes the full
OCSPResponse DER (byte-exact, what create --ocsp-file consumes) to
--out:

  asice ocsp fetch --cert signer.pem --out resp.der --chain chain.pem

The responder URL is the signer's AIA id-ad-ocsp entry by default;
--url overrides it. The signer's issuer comes from --issuer or the
--chain entry whose subject matches the signer's issuer name.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return &usageErr{msg: fmt.Sprintf("unknown command %q", args[0])}
			}
			err := runOCSPFetchCmd(cmd.Context(), cmd.OutOrStdout(), in)
			if isUsageError(err) {
				return err
			}
			if err != nil {
				return &opError{err: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&in.cert, "cert", "", "signer certificate (single PEM): the subject of the attestation (required)")
	cmd.Flags().StringVar(&in.out, "out", "", "output path for the full OCSPResponse DER (required)")
	cmd.Flags().StringVar(&in.issuer, "issuer", "", "signer issuer certificate (single PEM); wins over --chain")
	cmd.Flags().StringVar(&in.chain, "chain", "", "PEM chain: the certificate whose subject matches the signer's issuer name is the issuer")
	cmd.Flags().StringVar(&in.url, "url", "", "OCSP responder URL (default: the signer's AIA id-ad-ocsp entry)")
	cmd.Flags().DurationVar(&in.timeout, "timeout", 10*time.Second, "HTTP client timeout")
	return cmd
}

// runOCSPFetchCmd validates ocspFetchInput, runs ocsp.Fetch, writes the
// response DER, and prints the one-line summary. A *usageErr is a usage
// error (exit 2); any other error is a fetch failure (exit 1).
func runOCSPFetchCmd(ctx context.Context, stdout io.Writer, in ocspFetchInput) error {
	if in.cert == "" {
		return &usageErr{msg: "--cert is required (signer certificate)"}
	}
	if in.out == "" {
		return &usageErr{msg: "--out is required (output path)"}
	}
	signerPEM, err := os.ReadFile(in.cert)
	if err != nil {
		return fmt.Errorf("read --cert: %w", err)
	}
	signers, err := asic.ParsePEMCerts(signerPEM)
	if err != nil {
		return fmt.Errorf("parse --cert: %w", err)
	}
	if len(signers) != 1 {
		return fmt.Errorf("parse --cert: must hold exactly one certificate, got %d", len(signers))
	}
	var issuerPEM []byte
	if in.issuer != "" {
		issuerPEM, err = os.ReadFile(in.issuer)
		if err != nil {
			return fmt.Errorf("read --issuer: %w", err)
		}
	}
	var issuers []*x509.Certificate
	if len(issuerPEM) > 0 {
		issuers, err = asic.ParsePEMCerts(issuerPEM)
		if err != nil {
			return fmt.Errorf("parse --issuer: %w", err)
		}
		if len(issuers) != 1 {
			return fmt.Errorf("parse --issuer: must hold exactly one certificate, got %d", len(issuers))
		}
	}
	var chainPEM []byte
	if in.chain != "" {
		chainPEM, err = os.ReadFile(in.chain)
		if err != nil {
			return fmt.Errorf("read --chain: %w", err)
		}
	}
	chain, err := asic.ParsePEMCerts(chainPEM)
	if err != nil {
		return fmt.Errorf("parse --chain: %w", err)
	}

	var issuer *x509.Certificate
	if len(issuers) > 0 {
		issuer = issuers[0]
	}
	der, resp, err := ocsp.Fetch(ctx, ocsp.FetchOptions{
		Signer:  signers[0],
		Issuer:  issuer,
		Chain:   chain,
		URL:     in.url,
		Timeout: in.timeout,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(in.out, der, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", in.out, err)
	}
	producedAt := "unknown"
	if resp.Basic != nil {
		producedAt = resp.Basic.ProducedAt.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(stdout, "ocsp: %s producedAt=%s -> %s\n", resp.StatusName(), producedAt, in.out)
	return nil
}
