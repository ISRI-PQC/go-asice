// Package crypto — the tsa-domain crypto backend boundary (ADR 0004):
// the digest, CMS signature, and certificate chain operations the tsa
// package's code paths actually invoke, behind per-domain interfaces.
// The standard-library implementations (NewStd...) are the default; an
// alternative backend (HSM, post-quantum) implements the same
// interfaces and is selected at the application entry point —
// constructor/parameter injection, no package-level defaults.
package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// DigestModule computes message digests by RFC 3161 / CMS hash
// algorithm OID: the TST message imprint, the messageDigest signed
// attribute, and the signingCert(ingCertificateV2) certificate hash.
type DigestModule interface {
	// GetDigestFunc returns a closure that digests input with the
	// algorithm identified by the OID. The algorithm is selected once
	// at creation time; the closure returns an error when the
	// algorithm is unsupported.
	GetDigestFunc(algo asn1.ObjectIdentifier) func(input []byte) ([]byte, error)
}

// SignatureVerifierModule verifies the CMS SignerInfo signature of a
// TimeStampToken over the signed attributes re-encoded as a SET OF (the
// CMS encoding).
type SignatureVerifierModule interface {
	// VerifySignature verifies sig over signedAttrs with the
	// certificate's public key, the signature algorithm identified by
	// the OID.
	VerifySignature(cert *x509.Certificate, sigAlgo asn1.ObjectIdentifier, signedAttrs, sig []byte) error
}

// CertificateChainModule verifies the TSA signing certificate: the
// chain to the configured roots at the TST genTime and the TSA purpose
// bits (KeyUsage digitalSignature, EKU time-stamping).
type CertificateChainModule interface {
	VerifyChain(cert *x509.Certificate, roots, intermediates []*x509.Certificate, at time.Time) error
}
