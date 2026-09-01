package crypto

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/isri-pqc/asice/tsa"
	tsacrypto "github.com/isri-pqc/asice/tsa/crypto"
	xcrypto "github.com/isri-pqc/xmlsig/crypto"
)

// === Standard XMLSignatureSignerModule / XMLSignatureVerifierModule ===
//
// The implementations are the xmlsig standard modules. The ASiC-E
// ECDSA SignatureValue encoding is the spec-mandated raw r||s
// (fixed-width big-endian halves, W3C XML Signature 1.1 section
// 6.4.3, RFC 4050 section 3.3 / IEEE 1363 E3.1), which xmlsig
// produces and verifies on both paths; RSA is PKCS#1 v1.5 and the
// digest contract is encoding-agnostic, so the asic code reuses the
// xmlsig standard digest module. The wrappers exist as the
// asic-domain seam for alternative backends (ADR 0004).

// NewStdSignerModule returns the standard asic signer module over the
// private key and the signature hash algorithm (the ASiC-E domain
// always uses SHA-256).
func NewStdSignerModule(signer crypto.Signer, hashAlgo crypto.Hash) (xcrypto.XMLSignatureSignerModule, error) {
	return xcrypto.NewStdXMLSignatureSignerModule(signer, hashAlgo)
}

// NewStdVerifierModule returns the standard asic signature verifier
// (see the section above).
func NewStdVerifierModule() xcrypto.XMLSignatureVerifierModule {
	return xcrypto.NewStdXMLStandardCryptoVerifierModuleWithNoRevocationCheck()
}

// === Standard CertificateChainModule (Go's standard crypto/x509) ===

type standardCertificateChainModule struct{}

var _ CertificateChainModule = (*standardCertificateChainModule)(nil)

// NewStdCertificateChainModule returns the standard BDOC certificate
// chain verifier.
func NewStdCertificateChainModule() CertificateChainModule {
	return &standardCertificateChainModule{}
}

// VerifyChain checks the signer certificate the way the Estonian
// e-voting collector's certificate check does: the leaf requires the
// ContentCommitment key-usage bit, SHA-1-signed certificates are
// rejected with a clear
// message (Go >= 1.24 crypto/x509 cannot verify SHA-1 signatures, so
// the leaf is pre-scanned), and the chain builds edge by edge from the
// signer to a supplied trust anchor — the issuer signature is checked
// per edge (CheckSignatureFrom) and every certificate's validity
// window covers the signing time.
//
// The walk implements the collector's semantics rather than
// crypto/x509.Verify: Go's Verify additionally enforces its own
// key-usage/CA-bit strictness (checkChainForKeyUsage) that the
// collector does not, which diverges from the collector's verdicts on
// the SK test fixture chains (testEIDTS / testMIDTS pass the collector
// but fail Go's Verify). Supplied trust
// certificates are likewise NOT pre-scanned for SHA-1: a pool may carry
// legacy anchors a particular chain never uses (the SK trust YAMLs do).
func (m standardCertificateChainModule) VerifyChain(cert *x509.Certificate, roots, intermediates []*x509.Certificate, at time.Time) error {
	if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return fmt.Errorf("signer certificate lacks KeyUsage contentCommitment (required for BDOC signatures)")
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return fmt.Errorf("SHA-1 signature unsupported: signer certificate is SHA-1-signed (Go >= 1.24 crypto/x509 cannot verify SHA-1 signatures; the collector fails identically)")
	}
	pool := make([]*x509.Certificate, 0, len(roots)+len(intermediates))
	pool = append(pool, intermediates...)
	pool = append(pool, roots...)

	chain := []*x509.Certificate{cert}
	current := cert
	for {
		if err := m.validAt(current, at); err != nil {
			return fmt.Errorf("certificate chain verification failed: %w", err)
		}
		if m.poolContains(roots, current) {
			break // current is a supplied trust anchor
		}
		var issuer *x509.Certificate
		for _, cand := range pool {
			if !bytes.Equal(cand.RawSubject, current.RawIssuer) {
				continue
			}
			if err := current.CheckSignatureFrom(cand); err != nil {
				continue
			}
			issuer = cand
			break
		}
		if issuer == nil {
			return fmt.Errorf("certificate chain verification failed: no issuer of %q found among the supplied trust certificates", chainSubjectLabel(current))
		}
		chain = append(chain, issuer)
		current = issuer
		if len(chain) > 16 {
			return fmt.Errorf("certificate chain verification failed: chain longer than 16 certificates")
		}
	}
	return nil
}

// validAt reports whether cert's validity window covers at.
func (m standardCertificateChainModule) validAt(cert *x509.Certificate, at time.Time) error {
	if at.Before(cert.NotBefore) {
		return fmt.Errorf("certificate %q is not yet valid at the signing time", chainSubjectLabel(cert))
	}
	if at.After(cert.NotAfter) {
		return fmt.Errorf("certificate %q has expired at the signing time", chainSubjectLabel(cert))
	}
	return nil
}

// poolContains reports whether cert (DER-exact) is one of roots.
func (m standardCertificateChainModule) poolContains(roots []*x509.Certificate, cert *x509.Certificate) bool {
	for _, r := range roots {
		if bytes.Equal(r.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

// chainSubjectLabel renders a short subject label for error messages.
func chainSubjectLabel(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

// === Standard OCSPVerifierModule (Go's standard crypto/x509) ===

type standardOCSPVerifierModule struct{}

var _ OCSPVerifierModule = (*standardOCSPVerifierModule)(nil)

// NewStdOCSPVerifierModule returns the standard OCSP response
// verifier.
func NewStdOCSPVerifierModule() OCSPVerifierModule {
	return &standardOCSPVerifierModule{}
}

// ocspSignatureAlgorithms maps the OCSP response signature algorithm
// OIDs the Estonian e-voting collector accepts (the RSA SHA-2/3/4
// variants only) to crypto/x509 algorithm identifiers.
var ocspSignatureAlgorithms = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
}

func (m standardOCSPVerifierModule) VerifyResponseSignature(responder *x509.Certificate, tbs, sig []byte, sigAlgo asn1.ObjectIdentifier) error {
	alg, ok := ocspSignatureAlgorithms[sigAlgo.String()]
	if !ok {
		return fmt.Errorf("unsupported OCSP response signature algorithm %s", sigAlgo)
	}
	if err := responder.CheckSignature(alg, tbs, sig); err != nil {
		return fmt.Errorf("the OCSP response signature does not verify with the responder: %v", err)
	}
	return nil
}

func (m standardOCSPVerifierModule) VerifyResponderCertificate(cert, issuer *x509.Certificate, at time.Time) error {
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		CurrentTime: at,
	}); err != nil {
		return fmt.Errorf("verify embedded OCSP responder %s against the signer issuer: %w",
			chainSubjectLabel(cert), err)
	}
	return nil
}

// === Standard TSTVerifierModule (over the tsa package's standard
// modules) ===

type standardTSTVerifierModule struct {
	validator *tsa.Validator
}

var _ TSTVerifierModule = (*standardTSTVerifierModule)(nil)

// NewStdTSTVerifierModule returns the standard TST verifier over the
// configured TSA signer pool and intermediate CAs. The pool is
// configured as the validator's root set: the Estonian e-voting
// collector's offline TST check
// identifies the signer from the trust YAML tsp.signers list and never
// chains it to a PKI root (the 2023 SK fixtures' TSA CA is not in the
// trust YAML either), so a pool entry verifies as its own root, and a
// TST signed by a certificate outside the pool is still rejected.
func NewStdTSTVerifierModule(tstSigners, intermediates []*x509.Certificate) TSTVerifierModule {
	return &standardTSTVerifierModule{validator: &tsa.Validator{
		Roots:                   tstSigners,
		Intermediates:           intermediates,
		TSTSigners:              tstSigners,
		DigestModule:            tsacrypto.NewStdDigestModule(),
		SignatureVerifierModule: tsacrypto.NewStdSignatureVerifierModule(),
		ChainModule:             tsacrypto.NewStdCertificateChainModule(),
	}}
}

func (m standardTSTVerifierModule) VerifyTST(token, data []byte) (time.Time, error) {
	return m.validator.Check(token, data, tsa.CheckOptions{})
}
