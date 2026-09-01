package crypto

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Domain errors returned by the standard crypto implementations.
var (
	ErrUnsupportedDigestAlgorithm    = errors.New("tsa: unsupported digest algorithm")
	ErrUnsupportedSignatureAlgorithm = errors.New("tsa: unsupported CMS signature algorithm")
)

// === Standard DigestModule (Go's standard crypto library) ===

type standardDigestModule struct{}

var _ DigestModule = (*standardDigestModule)(nil)

// NewStdDigestModule returns the standard digest module.
func NewStdDigestModule() DigestModule {
	return &standardDigestModule{}
}

// digestAlgorithms maps the hash algorithm OIDs the standard
// implementation supports (SHA-1 — the signingCert attribute v1 — plus
// the SHA-2 family used by imprints, messageDigest attributes, and
// signingCertificateV2).
var digestAlgorithms = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

func (s standardDigestModule) GetDigestFunc(algo asn1.ObjectIdentifier) func(input []byte) ([]byte, error) {
	return func(input []byte) ([]byte, error) {
		h, ok := digestAlgorithms[algo.String()]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedDigestAlgorithm, algo)
		}
		hh := h.New()
		hh.Write(input)
		return hh.Sum(nil), nil
	}
}

// === Standard SignatureVerifierModule (Go's standard crypto library) ===

type standardSignatureVerifierModule struct{}

var _ SignatureVerifierModule = (*standardSignatureVerifierModule)(nil)

// NewStdSignatureVerifierModule returns the standard CMS signature
// verifier.
func NewStdSignatureVerifierModule() SignatureVerifierModule {
	return &standardSignatureVerifierModule{}
}

// signatureAlgorithms maps the CMS signature algorithm OIDs the
// standard implementation supports: the RSA and ECDSA families, the
// set the Estonian e-voting collector's TSP client accepts.
var signatureAlgorithms = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
}

func (m standardSignatureVerifierModule) VerifySignature(cert *x509.Certificate, sigAlgo asn1.ObjectIdentifier, signedAttrs, sig []byte) error {
	alg, ok := signatureAlgorithms[sigAlgo.String()]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedSignatureAlgorithm, sigAlgo)
	}
	if err := cert.CheckSignature(alg, signedAttrs, sig); err != nil {
		return fmt.Errorf("tsa: signature does not verify: %w", err)
	}
	return nil
}

// === Standard CertificateChainModule (Go's standard crypto/x509) ===

type standardCertificateChainModule struct{}

var _ CertificateChainModule = (*standardCertificateChainModule)(nil)

// NewStdCertificateChainModule returns the standard TSA certificate
// chain verifier.
func NewStdCertificateChainModule() CertificateChainModule {
	return &standardCertificateChainModule{}
}

func (m standardCertificateChainModule) VerifyChain(cert *x509.Certificate, roots, intermediates []*x509.Certificate, at time.Time) error {
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	intermediatePool := x509.NewCertPool()
	for _, i := range intermediates {
		intermediatePool.AddCert(i)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Intermediates: intermediatePool,
	}); err != nil {
		return fmt.Errorf("tsa: TSA certificate does not chain to a configured root at genTime: %w", err)
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("tsa: TSA certificate KeyUsage lacks digitalSignature")
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return nil
		}
	}
	return errors.New("tsa: TSA certificate lacks the time-stamping extended key usage")
}
