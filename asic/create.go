// Package asic — high-level creation orchestration (PLAN.md Task 9):
// signer material parsing, document loading, and one-call container
// creation over SignBES / SignTS / WriteContainer. No new cryptography:
// signing is delegated to the BES/TS signature renderers.
package asic

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	asiccrypto "github.com/isri-pqc/asice/asic/crypto"
	xcrypto "github.com/isri-pqc/go-xmlsig/crypto"
)

// Signer pairs a signer certificate with its XML-DSig signer module.
// One Signer produces one signature document (S0, S1, ... in
// CreateOptions order).
type Signer struct {
	// Certificate is the signer certificate (KeyInfo / SigningCertificate).
	Certificate *x509.Certificate
	// SignerModule signs the signature documents (ADR 0004: the key
	// material and its backend live inside the module; the domain never
	// holds a raw crypto.Signer for the signing operation).
	SignerModule xcrypto.XMLSignatureSignerModule
}

// CreateOptions configures Create.
type CreateOptions struct {
	// Docs are the data files (>=1), in container order.
	Docs []Doc

	// Signers produce the signature documents (>=1), in order:
	// Signers[i] signs S{i} (META-INF/signatures{i}.xml).
	Signers []Signer

	// DigestModule computes the data file and SignedProperties digests
	// (shared by all signers; ADR 0004). Required.
	DigestModule xcrypto.XMLDigestModule

	// Profile selects the signature profile; zero is BES.
	Profile Profile

	// SigningTime is the xades:SigningTime of every signature. It must
	// be non-zero: Create performs no wall-clock reads.
	SigningTime time.Time

	// --- TS profile only (ignored for BES) ---

	// OCSPResponse is the DER basic OCSP response for the signer
	// certificate, embedded in xades:RevocationValues.
	OCSPResponse []byte

	// TimeStamp produces an RFC 3161 TST over the given data (for
	// example a tsa.Client bound to a TSA endpoint). SignTS calls it
	// once per signature, with the C14N 1.1 bytes of that signature's
	// ds:SignatureValue element.
	TimeStamp func(data []byte) ([]byte, error)

	// TSCertificates are embedded in xades:CertificateValues in order;
	// exactly two: [0] the OCSP responder certificate, [1] the CA
	// certificate.
	TSCertificates []*x509.Certificate
}

// Create renders the signature documents (one per Signer, BES via
// SignBES, TS via SignTS) and writes a complete ASiC-E container to w.
func Create(w io.Writer, opts CreateOptions) error {
	if len(opts.Docs) == 0 {
		return errors.New("asic: Create needs at least one data file")
	}
	if len(opts.Signers) == 0 {
		return errors.New("asic: Create needs at least one signer")
	}
	if opts.DigestModule == nil {
		return errors.New("asic: Create requires a digest module (DigestModule)")
	}
	if opts.SigningTime.IsZero() {
		return errors.New("asic: Create requires a non-zero SigningTime (no wall-clock default)")
	}
	if opts.Profile != ProfileBES && opts.Profile != ProfileTS {
		return fmt.Errorf("asic: unknown profile %d", opts.Profile)
	}
	if opts.Profile == ProfileTS {
		if opts.TimeStamp == nil {
			return errors.New("asic: TS profile requires a TimeStamp provider")
		}
		if len(opts.OCSPResponse) == 0 {
			return errors.New("asic: TS profile requires an OCSP response")
		}
		if len(opts.TSCertificates) != 2 {
			return fmt.Errorf("asic: TS profile requires exactly two TSCertificates (OCSP responder, CA), got %d", len(opts.TSCertificates))
		}
	}

	sigs := make([][]byte, 0, len(opts.Signers))
	for i, s := range opts.Signers {
		if s.Certificate == nil || s.SignerModule == nil {
			return fmt.Errorf("asic: signer %d is incomplete (certificate and signer module required)", i)
		}
		var (
			sig []byte
			err error
		)
		switch opts.Profile {
		case ProfileTS:
			sig, err = SignTS(i, s.SignerModule, opts.DigestModule, s.Certificate, opts.Docs, opts.SigningTime, TSData{
				TimeStamp:    opts.TimeStamp,
				OCSPResponse: opts.OCSPResponse,
				Certificates: opts.TSCertificates,
			})
		default:
			sig, err = SignBES(i, s.SignerModule, opts.DigestModule, s.Certificate, opts.Docs, opts.SigningTime)
		}
		if err != nil {
			return fmt.Errorf("asic: sign S%d: %w", i, err)
		}
		sigs = append(sigs, sig)
	}
	return WriteContainer(w, opts.Docs, sigs...)
}

// ParseSigner reads a signer file: PEM blocks containing exactly one
// CERTIFICATE (the signer certificate) and exactly one private key
// block ("PRIVATE KEY" PKCS#8, "RSA PRIVATE KEY" PKCS#1, or
// "EC PRIVATE KEY" SEC1). Block order does not matter. The returned
// Signer carries the standard signer module over the parsed key (the
// default implementation, ADR 0004).
func ParseSigner(b []byte) (Signer, error) {
	var (
		cert      *x509.Certificate
		key       crypto.Signer
		keyBlocks int
		keyErr    error
	)
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if cert != nil {
				return Signer{}, errors.New("asic: signer file has more than one CERTIFICATE block")
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return Signer{}, fmt.Errorf("asic: parse signer certificate: %w", err)
			}
			cert = c
		default:
			// Count every private-key-typed block, including ones that
			// fail to decode: the contract is exactly one key block, so
			// a corrupt first block followed by a valid second is still
			// a two-key file.
			keyBlocks++
			if keyBlocks > 1 {
				return Signer{}, errors.New("asic: signer file has more than one private key block")
			}
			k, err := parsePrivateKeyBlock(block)
			if err != nil {
				keyErr = err
				continue
			}
			key = k
		}
	}
	if cert == nil {
		return Signer{}, errors.New("asic: signer file has no PEM CERTIFICATE block")
	}
	if key == nil {
		if keyErr != nil {
			return Signer{}, fmt.Errorf("asic: signer file private key: %w", keyErr)
		}
		return Signer{}, errors.New("asic: signer file has no PEM private key block")
	}
	if !signerKeyMatchesCert(key, cert) {
		return Signer{}, errors.New("asic: signer private key does not match the certificate")
	}
	// The standard signer module is the default implementation
	// (ADR 0004); an alternative backend wraps its own signer module
	// over the parsed key instead.
	sm, err := asiccrypto.NewStdSignerModule(key, crypto.SHA256)
	if err != nil {
		return Signer{}, fmt.Errorf("asic: signer file private key: %w", err)
	}
	return Signer{Certificate: cert, SignerModule: sm}, nil
}

// ParsePrivateKey decodes a private key from PEM (PKCS#8
// "PRIVATE KEY", PKCS#1 "RSA PRIVATE KEY", or SEC1 "EC PRIVATE KEY"
// block) or from a single DER encoding of one of those three.
func ParsePrivateKey(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		// Whole-buffer DER of one of the three forms.
		raw, err := func() (any, error) {
			if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
				return k, nil
			}
			if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
				return k, nil
			}
			return x509.ParseECPrivateKey(b)
		}()
		if err == nil {
			if key, ok := raw.(crypto.Signer); ok {
				return key, nil
			}
		}
		return nil, errors.New("asic: no PEM block and no recognizable DER private key")
	}
	return parsePrivateKeyBlock(block)
}

// parsePrivateKeyBlock decodes one private-key PEM block.
func parsePrivateKeyBlock(block *pem.Block) (crypto.Signer, error) {
	var raw any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		raw, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		raw, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		raw, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("asic: unsupported PEM block type %q (want a private key block)", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("asic: parse %s key: %w", block.Type, err)
	}
	key, ok := raw.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("asic: %s key is not a crypto.Signer (%T)", block.Type, raw)
	}
	return key, nil
}

// signerKeyMatchesCert reports whether the parsed private key's public
// key equals the certificate's public key. It compares the PKIX
// encodings, which covers every key type parsePrivateKeyBlock can
// return (*rsa.PrivateKey, *ecdsa.PrivateKey, and
// *ed25519.PrivateKey via PKCS#8) without per-type comparisons.
func signerKeyMatchesCert(key crypto.Signer, cert *x509.Certificate) bool {
	kder, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return false
	}
	cder, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(kder, cder)
}

// MediaTypeForName guesses the ODF manifest media type from the file
// extension; unknown extensions get application/octet-stream.
func MediaTypeForName(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt", ".text":
		return "text/plain"
	case ".pdf":
		return "application/pdf"
	case ".xml":
		return "application/xml"
	case ".json":
		return "application/json"
	case ".csv":
		return "text/csv"
	case ".html", ".htm":
		return "text/html"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	default:
		return "application/octet-stream"
	}
}

// DocsFromPaths reads each path into a Doc: the flat base name (no
// subfolders — the ASiC-E layout is flat), the media type from the
// extension, and the raw content.
func DocsFromPaths(paths []string) ([]Doc, error) {
	if len(paths) == 0 {
		return nil, errors.New("asic: no data files")
	}
	docs := make([]Doc, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("asic: read %s: %w", p, err)
		}
		name := filepath.Base(p)
		docs = append(docs, Doc{Name: name, MediaType: MediaTypeForName(name), Data: data})
	}
	return docs, nil
}
