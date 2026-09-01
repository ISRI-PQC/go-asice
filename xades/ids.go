// Package xades builds the XAdES property XML of ASiC-E signature
// documents (PLAN.md §1.2) in the XAdES TS 101 893 v1.3.2 namespace as
// etree elements.
//
// The rendered document layout is house style (2-space indentation,
// single-line base64), not part of the interop contract: the canonical
// bytes depend on the layout but are self-consistent, because we
// canonicalize and sign the final rendering (inclusive C14N 1.1) and
// the Estonian e-voting collector (the library's interop target; see
// the README) re-canonicalizes the parsed document with the same
// algorithm. The hard constraints are the TST-flow self-consistency
// (the TST imprints the canonical ds:SignatureValue as rendered) and
// the collector's structural parser (element shape/order/Id/Type).
// See docs/adr/0001-canonicalization-and-container-rules.md.
package xades

import "strconv"

// Namespace URIs of the signature document elements.
const (
	// NSASIC is the ASiC-E XAdES wrapper namespace (v1.2.1).
	NSASIC = "http://uri.etsi.org/02918/v1.2.1#"
	// NSDSIG is the XML Digital Signature namespace.
	NSDSIG = "http://www.w3.org/2000/09/xmldsig#"
	// NSXAdES is the XAdES v1.3.2 namespace of the property elements.
	NSXAdES = "http://uri.etsi.org/01903/v1.3.2#"
)

// Algorithm URIs the property XML uses (the Estonian e-voting
// collector's digest-method allowlist; PLAN §5 locks SHA-256 for
// emission).
const (
	// DigestMethodSHA256 is the ds:DigestMethod algorithm of every
	// digest in the property XML.
	DigestMethodSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	// SignedPropertiesRefType is the ds:Reference Type of the
	// SignedProperties reference.
	SignedPropertiesRefType = "http://uri.etsi.org/01903#SignedProperties"
)

// Id scheme of the signature document: every identifier of signature k
// (the signatures{k}.xml document carries S{k}) derives from the
// signature index.
//
//	SignatureID(k) → S0, ReferenceID(0, 2) → S0-RefId2,
//	SignatureValueID(0) → S0-SIG, SignedPropertiesID(0) →
//	S0-SignedProperties, TimestampID(0) → S0-T0,
//	ResponderCertificateID(0) → S0-RESPONDER_CERT,
//	CACertificateID(0) → S0-CA-CERT, OCSPValueID(0) → N0.

// SignatureID is the ds:Signature Id.
func SignatureID(k int) string { return "S" + strconv.Itoa(k) }

// ReferenceID is the ds:Reference Id of the i-th referenced element
// (data files first, the SignedProperties reference last).
func ReferenceID(k, i int) string { return SignatureID(k) + "-RefId" + strconv.Itoa(i) }

// SignatureValueID is the ds:SignatureValue Id.
func SignatureValueID(k int) string { return SignatureID(k) + "-SIG" }

// SignedPropertiesID is the xades:SignedProperties Id.
func SignedPropertiesID(k int) string { return SignatureID(k) + "-SignedProperties" }

// SignedPropertiesURI is the ds:Reference URI of the SignedProperties
// reference.
func SignedPropertiesURI(k int) string { return "#" + SignedPropertiesID(k) }

// TimestampID is the xades:SignatureTimeStamp Id.
func TimestampID(k int) string { return SignatureID(k) + "-T0" }

// ResponderCertificateID is the Id of the OCSP responder's
// xades:EncapsulatedX509Certificate.
func ResponderCertificateID(k int) string { return SignatureID(k) + "-RESPONDER_CERT" }

// CACertificateID is the Id of a CA-chain xades:EncapsulatedX509Certificate.
func CACertificateID(k int) string { return SignatureID(k) + "-CA-CERT" }

// OCSPValueID is the xades:EncapsulatedOCSPValue Id.
func OCSPValueID(k int) string { return "N" + strconv.Itoa(k) }
