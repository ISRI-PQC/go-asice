// RFC 4514 issuer-name rendering with the byte semantics the interop
// contract with the Estonian e-voting collector (the library's interop
// target; see the README) pins: short-name map, most-specific-first
// order, and the collector's escaping (non-standard or non-string
// values hex-encoded from their DER). The rendered string must
// round-trip the collector's RDN decode + sequence-equality check
// against cert.Issuer (ExtraNames = Names) — the comparison its
// SigningCertificate verification performs — and byte-match the
// fixtures' ds:X509IssuerName values.

package xades

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// rdnShortNames maps attribute OIDs to the RFC 4514 short names the
// collector's issuer-name encoder uses.
var rdnShortNames = map[string]string{
	"1.2.840.113549.1.9.1": "emailAddress",
	"2.5.4.3":              "CN",
	"2.5.4.4":              "SN",
	"2.5.4.5":              "serialNumber",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "ST",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"2.5.4.42":             "GN",
	"2.5.4.97":             "organizationIdentifier",
}

// rdnEscapeRE marks the characters the collector's RFC 4514
// issuer-name encoder escapes.
var rdnEscapeRE = regexp.MustCompile(`(^#|^ |["+,;<=>\\]| $)`)

// EncodeRDNSequence encodes a relative-distinguished-name sequence into
// an RFC 4514 string byte-identically to the Estonian e-voting
// collector's RDN encoder.
//
// Go's pkix.Name stores every parsed attribute in Names in DER order;
// ToRDNSequence uses ExtraNames (which parsing leaves empty), so callers
// must set name.ExtraNames = name.Names first — exactly what the
// collector does
// before comparing issuer names.
func EncodeRDNSequence(dn pkix.RDNSequence) string {
	var parts []string
	for i := len(dn) - 1; i >= 0; i-- {
		var attrs []string
		for _, atv := range dn[i] {
			oid := atv.Type.String()
			short := rdnShortNames[oid]
			var value string
			if s, ok := atv.Value.(string); ok && short != "" {
				value = rdnEscapeRE.ReplaceAllString(s, `\$1`)
				value = strings.ReplaceAll(value, "\x00", "\\00")
			} else {
				// Hex-encoded DER of the value, like the collector's encoder.
				short = oid
				der, err := asn1.Marshal(atv.Value)
				if err != nil {
					// Unreachable for values Go's x509 accepts; fail
					// loudly.
					panic(fmt.Sprintf("xades: marshal RDN value %s: %v", oid, err))
				}
				value = "#" + hex.EncodeToString(der)
			}
			attrs = append(attrs, short+"="+value)
		}
		parts = append(parts, strings.Join(attrs, "+"))
	}
	return strings.Join(parts, ",")
}

// IssuerName renders the RFC 4514 issuer DN of cert for use in
// ds:X509IssuerName. It encodes cert.Issuer with ExtraNames = Names
// (the form the Estonian e-voting collector compares against), so the
// result round-trips the collector's RDN decode + sequence-equality
// check.
func IssuerName(cert *x509.Certificate) string {
	name := cert.Issuer
	name.ExtraNames = name.Names
	return EncodeRDNSequence(name.ToRDNSequence())
}
