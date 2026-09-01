// SignedProperties (BES core) rendering.

package xades

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/beevik/etree"
	xcrypto "github.com/isri-pqc/xmlsig/crypto"
	"github.com/isri-pqc/xmlsig/spec"
)

// File is one signed data file: the flat name (ds:Reference URI inside
// the container) and the DataObjectFormat media type (which must equal
// the ODF manifest media type, as the interop contract with the
// Estonian e-voting collector enforces).
type File struct {
	Name      string
	MediaType string
}

// SignedProperties builds the xades:SignedProperties element of the
// signature document in the BES core shape:
//
//	SignedSignatureProperties: SigningTime (RFC 3339 UTC) +
//	SigningCertificate (v1.3.2 Cert: CertDigest (DigestMethodSHA256
//	through dm) of the KeyInfo certificate DER + IssuerSerial with RFC
//	4514 issuer name and decimal serial). SignaturePolicyIdentifier is
//	absent (the Estonian e-voting collector rejects it in the BES/TS
//	profiles), and so are the optional
//	SignatureProductionPlace/SignerRole (allowed empty, unused).
//
//	SignedDataObjectProperties: one DataObjectFormat per data file
//	(ObjectReference = "#S{k}-RefId{i}", MimeType the only child).
//
// The element is detached: the caller inserts it into the signature
// document (ds:Object) before canonicalizing it, so the namespace
// context of the document root applies (ADR 0001 §1).
//
// dm computes the CertDigest (ADR 0004: the digest operation is a
// crypto module, not an embedded hash call).
func SignedProperties(k int, dm xcrypto.XMLDigestModule, cert *x509.Certificate, signingTime time.Time, files []File) (*etree.Element, error) {
	certDigest, err := dm.GetDigestFunc(spec.XMLDigestAlgorithmID(DigestMethodSHA256))(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("xades: SignedProperties: CertDigest: %w", err)
	}

	sp := etree.NewElement("xades:SignedProperties")
	sp.CreateAttr("Id", SignedPropertiesID(k))
	ssp := sp.CreateElement("xades:SignedSignatureProperties")
	ssp.CreateElement("xades:SigningTime").SetText(signingTime.UTC().Format(time.RFC3339))
	certEl := ssp.CreateElement("xades:SigningCertificate").CreateElement("xades:Cert")
	digestEl := certEl.CreateElement("xades:CertDigest")
	digestEl.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", DigestMethodSHA256)
	digestEl.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(certDigest))
	issEl := certEl.CreateElement("xades:IssuerSerial")
	issEl.CreateElement("ds:X509IssuerName").SetText(IssuerName(cert))
	issEl.CreateElement("ds:X509SerialNumber").SetText(cert.SerialNumber.String())

	dops := sp.CreateElement("xades:SignedDataObjectProperties")
	for i, f := range files {
		dof := dops.CreateElement("xades:DataObjectFormat")
		dof.CreateAttr("ObjectReference", "#"+ReferenceID(k, i))
		dof.CreateElement("xades:MimeType").SetText(f.MediaType)
	}
	return sp, nil
}

// QualifyingProperties wraps the SignedProperties element (sp) and, for
// the TS profile, the UnsignedProperties element (usp; pass nil for BES)
// in xades:QualifyingProperties with Target="#S{k}".
//
// The USP element is outside both canonicalized regions, so adding it
// after signing does not change the SignedProperties digest or the
// SignedInfo signature.
func QualifyingProperties(k int, sp, usp *etree.Element) *etree.Element {
	qp := etree.NewElement("xades:QualifyingProperties")
	qp.CreateAttr("Target", "#"+SignatureID(k))
	qp.AddChild(sp)
	if usp != nil {
		qp.AddChild(usp)
	}
	return qp
}
