// create subcommand: the create flow over asic.Create.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/isri-pqc/go-asice/asic"
	"github.com/isri-pqc/go-asice/tsa"
	tsacrypto "github.com/isri-pqc/go-asice/tsa/crypto"
	xcrypto "github.com/isri-pqc/go-xmlsig/crypto"
)

// createInput is the parsed create request (testable without a
// command).
type createInput struct {
	out         string
	certFile    string
	profile     string
	chainFile   string
	ocspFile    string
	tstURL      string
	tstSigners  string
	signingTime time.Time
	docs        []string
}

// runCreateCmd executes the create flow and reports progress to
// stderr. It returns a plain error on any failure (the CLI maps it to
// exit 1, the create/verify failure code). ctx bounds the create
// operation (the CLI passes the cobra command context); the TSA
// timestamp requests are additionally bounded by the tsa.Client
// package default timeout (tsa.DefaultTimeout).
func runCreateCmd(ctx context.Context, stderr io.Writer, in createInput) error {
	in.profile = strings.ToLower(strings.TrimSpace(in.profile))
	if in.out == "" {
		return errors.New("-o is required (output container path)")
	}
	if in.certFile == "" {
		return errors.New("--cert is required (signer certificate + private key file)")
	}
	if len(in.docs) == 0 {
		return errors.New("at least one document path is required")
	}
	var profile asic.Profile
	switch in.profile {
	case "bes", "":
		profile = asic.ProfileBES
	case "ts":
		profile = asic.ProfileTS
	default:
		return fmt.Errorf("unknown --profile %q (want bes or ts)", in.profile)
	}

	if profile == asic.ProfileTS {
		if in.ocspFile == "" {
			return errors.New("--ocsp-file is required for the ts profile")
		}
		if in.tstURL == "" {
			return errors.New("--tst is required for the ts profile")
		}
		if in.tstSigners == "" {
			return errors.New("--tst-signers is required for the ts profile")
		}
		if in.chainFile == "" {
			return errors.New("--chain is required for the ts profile")
		}
	}

	certRaw, err := os.ReadFile(in.certFile)
	if err != nil {
		return fmt.Errorf("read --cert: %w", err)
	}
	signer, err := asic.ParseSigner(certRaw)
	if err != nil {
		return fmt.Errorf("parse --cert: %w", err)
	}
	docs, err := asic.DocsFromPaths(in.docs)
	if err != nil {
		return err
	}

	// The standard crypto modules are the default implementations
	// (ADR 0004): the signer module was built by ParseSigner over the
	// parsed key, the digest module computes the file/SP digests.
	opts := asic.CreateOptions{
		Docs:         docs,
		Signers:      []asic.Signer{signer},
		Profile:      profile,
		SigningTime:  in.signingTime,
		DigestModule: xcrypto.NewStdXMLDigestModule(),
	}
	if profile == asic.ProfileTS {
		ocsp, err := os.ReadFile(in.ocspFile)
		if err != nil {
			return fmt.Errorf("read --ocsp-file: %w", err)
		}
		signersRaw, err := os.ReadFile(in.tstSigners)
		if err != nil {
			return fmt.Errorf("read --tst-signers: %w", err)
		}
		tstSigners, err := asic.ParsePEMCerts(signersRaw)
		if err != nil {
			return fmt.Errorf("parse --tst-signers: %w", err)
		}
		if len(tstSigners) == 0 {
			return errors.New("--tst-signers contains no certificates")
		}
		chainRaw, err := os.ReadFile(in.chainFile)
		if err != nil {
			return fmt.Errorf("read --chain: %w", err)
		}
		chain, err := asic.ParsePEMCerts(chainRaw)
		if err != nil {
			return fmt.Errorf("parse --chain: %w", err)
		}
		if len(chain) != 2 {
			return fmt.Errorf("--chain must contain exactly two certificates (OCSP responder, then CA), got %d", len(chain))
		}

		client := tsa.NewClient(in.tstURL)
		client.TSTSigners = tstSigners
		// The standard tsa crypto modules (the default implementations,
		// ADR 0004).
		client.DigestModule = tsacrypto.NewStdDigestModule()
		client.SignatureVerifierModule = tsacrypto.NewStdSignatureVerifierModule()
		opts.OCSPResponse = ocsp
		opts.TSCertificates = chain
		opts.TimeStamp = func(data []byte) ([]byte, error) {
			token, _, err := client.Create(ctx, data, nil)
			return token, err
		}
	}

	out, err := os.Create(in.out)
	if err != nil {
		return fmt.Errorf("create %s: %w", in.out, err)
	}
	defer out.Close()
	if err := asic.Create(out, opts); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "asice: wrote %s (%d document(s), profile %s)\n", in.out, len(docs), in.profileName())
	return nil
}

func (in createInput) profileName() string {
	if in.profile == "" {
		return "bes"
	}
	return in.profile
}
