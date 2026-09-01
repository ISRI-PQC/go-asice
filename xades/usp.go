// UnsignedProperties (TS profile) rendering.

package xades

import (
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

// Certificate is one embedded certificate of xades:CertificateValues
// with its document Id (e.g., ResponderCertificateID(0),
// CACertificateID(0)).
type Certificate struct {
	ID  string
	DER []byte
}

// UnsignedProperties builds the xades:UnsignedProperties element of
// the TS profile, in the fixture element order:
//
//	SignatureTimeStamp (Id "S{k}-T0", one EncapsulatedTimeStamp: the
//	RFC 3161 TST over the canonical ds:SignatureValue) →
//	CertificateValues (one EncapsulatedX509Certificate per embedded
//	certificate: OCSP responder first, then the CA chain) →
//	RevocationValues (OCSPValues → exactly one EncapsulatedOCSPValue;
//	CRL is not allowed).
//
// The element is detached: the caller inserts it into the signature
// document (xades:QualifyingProperties) after signing. UnsignedProperties
// is outside both canonicalized regions, so its presence changes no
// digest or signature.
func UnsignedProperties(k int, tst []byte, certs []Certificate, ocsp []byte) (*etree.Element, error) {
	if len(tst) == 0 {
		return nil, fmt.Errorf("xades: UnsignedProperties: empty timestamp token")
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("xades: UnsignedProperties: no embedded certificates")
	}
	for i, c := range certs {
		if len(c.DER) == 0 {
			return nil, fmt.Errorf("xades: UnsignedProperties: certificate %d has no DER", i)
		}
	}
	if len(ocsp) == 0 {
		return nil, fmt.Errorf("xades: UnsignedProperties: empty OCSP response")
	}

	usp := etree.NewElement("xades:UnsignedProperties")
	uspp := usp.CreateElement("xades:UnsignedSignatureProperties")
	tstEl := uspp.CreateElement("xades:SignatureTimeStamp")
	tstEl.CreateAttr("Id", TimestampID(k))
	tstEl.CreateElement("xades:EncapsulatedTimeStamp").SetText(base64.StdEncoding.EncodeToString(tst))
	certVals := uspp.CreateElement("xades:CertificateValues")
	for _, c := range certs {
		cEl := certVals.CreateElement("xades:EncapsulatedX509Certificate")
		cEl.CreateAttr("Id", c.ID)
		cEl.SetText(base64.StdEncoding.EncodeToString(c.DER))
	}
	ocspEl := uspp.CreateElement("xades:RevocationValues").CreateElement("xades:OCSPValues").CreateElement("xades:EncapsulatedOCSPValue")
	ocspEl.CreateAttr("Id", OCSPValueID(k))
	ocspEl.SetText(base64.StdEncoding.EncodeToString(ocsp))
	return usp, nil
}
