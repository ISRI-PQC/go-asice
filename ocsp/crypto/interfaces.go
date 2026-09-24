// Package crypto holds the per-domain crypto module interfaces and
// the standard-library implementations of the ocsp domain (ADR 0004):
// the domain code performs no direct crypto primitives — the RFC 6960
// CertID digests go through the injected DigestModule.
package crypto

import "encoding/asn1"

// DigestModule computes the RFC 6960 CertID message digests (the
// issuerNameHash and issuerKeyHash of the certificate identifier):
// the hash algorithm is selected by OID. RFC 6960 section 4.1.1 fixes
// it to SHA-1 (1.3.14.3.2.26); the request's hashAlgorithm field
// carries that OID.
type DigestModule interface {
	// GetDigestFunc returns a closure that digests input with the
	// algorithm identified by the OID. The algorithm is selected once
	// at creation time; the closure returns an error when the
	// algorithm is unsupported.
	GetDigestFunc(algo asn1.ObjectIdentifier) func(input []byte) ([]byte, error)
}
