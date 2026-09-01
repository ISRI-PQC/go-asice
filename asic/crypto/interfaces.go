// Package crypto — the asic-domain crypto backend boundary (ADR
// 0004).
//
// The XML-DSig operations (digest, signing, signature verification)
// consume the xmlsig/crypto interface contracts — the asic code path
// invokes XML-DSig operations, so it uses those interfaces rather than
// copying them. NewStdSignerModule / NewStdVerifierModule are thin
// wrappers over the xmlsig standard modules, which produce and
// verify the spec-mandated ECDSA SignatureValue encoding (raw r||s,
// fixed-width big-endian — W3C XML Signature 1.1 section 6.4.3,
// RFC 4050 section 3.3); the digest contract is encoding-agnostic
// and reuses the xmlsig standard digest module. This package also defines the remaining asic-domain
// operations: BDOC certificate chain verification (the collector's
// certificate-check semantics), embedded OCSP response verification,
// and RFC 3161 TST verification.
//
// All standard-library implementations (NewStd...) are the default; an
// alternative backend (HSM, post-quantum) implements the same
// interfaces and is selected at the application entry point —
// constructor/parameter injection, no package-level defaults.
package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// CertificateChainModule verifies a BDOC signer certificate the way
// the Estonian e-voting collector's certificate check does: the leaf
// requires the ContentCommitment key-usage bit, SHA-1-signed leaves
// are rejected,
// and the chain builds edge by edge from the signer to a supplied
// trust anchor (issuer signature per edge, validity window at the
// signing time).
type CertificateChainModule interface {
	VerifyChain(cert *x509.Certificate, roots, intermediates []*x509.Certificate, at time.Time) error
}

// OCSPVerifierModule verifies the cryptographic parts of the embedded
// OCSP response (RFC 6960): the response signature over the
// tbsResponseData with the responder certificate, and the embedded
// responder certificate against the signer's issuer with the
// OCSPSigning EKU.
type OCSPVerifierModule interface {
	// VerifyResponseSignature verifies the basic OCSP response
	// signature (sig over tbs) with the responder certificate, the
	// signature algorithm identified by the OID.
	VerifyResponseSignature(responder *x509.Certificate, tbs, sig []byte, sigAlgo asn1.ObjectIdentifier) error
	// VerifyResponderCertificate verifies the embedded responder
	// certificate against the signer's issuer certificate (the
	// issuer-fallback path) at the signing time, with the OCSPSigning
	// extended key usage.
	VerifyResponderCertificate(cert, issuer *x509.Certificate, at time.Time) error
}

// TSTVerifierModule verifies an RFC 3161 TST over the exact data and
// returns the token's generation time (stored-token semantics: no
// genTime freshness check against the current time).
type TSTVerifierModule interface {
	VerifyTST(token, data []byte) (genTime time.Time, err error)
}
