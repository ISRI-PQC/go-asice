// Self-checks of the rendered XAdES properties, mirroring the property
// verification the Estonian e-voting collector (the library's interop
// target; see the README "Verification" section) performs on a BDOC
// container: the SigningCertificate invariants (CertDigest over the
// KeyInfo certificate DER, decimal serial, RFC 4514 issuer name) and
// the DataObjectFormat invariants (one per signed file, MimeType
// matching the manifest media type). These check a parsed signature
// document produced by this package; the acceptance bar remains the
// collector's own container verification, enforced by the external
// acceptance harness (maintained outside this repo).

package xades

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	xcrypto "github.com/isri-pqc/xmlsig/crypto"
	"github.com/isri-pqc/xmlsig/spec"
)

// digestMethods is the ds:DigestMethod algorithm allowlist the
// Estonian e-voting collector accepts (SHA-256, SHA-384, SHA-512).
var digestMethods = map[string]struct{}{
	"http://www.w3.org/2001/04/xmlenc#sha256":       {},
	"http://www.w3.org/2001/04/xmldsig-more#sha384": {},
	"http://www.w3.org/2001/04/xmlenc#sha512":       {},
}

// CheckSigningCertificate verifies the xades:SigningCertificate inside
// the xades:SignedSignatureProperties element ssp against the signer
// certificate cert, as the interop contract with the Estonian
// e-voting collector requires (XAdES TS 101 893 SigningCertificate):
//
//   - the CertDigest must digest the exact certificate DER (cert.Raw)
//     with an algorithm from the digestMethods allowlist;
//   - X509SerialNumber must equal the certificate's decimal serial;
//   - X509IssuerName must equal the RFC 4514 rendering of the
//     certificate's issuer (IssuerName).
func CheckSigningCertificate(dm xcrypto.XMLDigestModule, ssp *etree.Element, cert *x509.Certificate) error {
	iss := ssp.FindElement("xades:SigningCertificate/xades:Cert/xades:IssuerSerial")
	if iss == nil {
		return fmt.Errorf("xades: check: IssuerSerial not found")
	}
	certDigest := ssp.FindElement("xades:SigningCertificate/xades:Cert/xades:CertDigest")
	if certDigest == nil {
		return fmt.Errorf("xades: check: CertDigest not found")
	}
	method := certDigest.FindElement("ds:DigestMethod")
	if method == nil {
		return fmt.Errorf("xades: check: CertDigest DigestMethod not found")
	}
	methodURI := method.SelectAttrValue("Algorithm", "")
	if _, ok := digestMethods[methodURI]; !ok {
		return fmt.Errorf("xades: check: unsupported CertDigest algorithm %q", methodURI)
	}
	digest, err := dm.GetDigestFunc(spec.XMLDigestAlgorithmID(methodURI))(cert.Raw)
	if err != nil {
		return fmt.Errorf("xades: check: CertDigest: %w", err)
	}
	want := base64.StdEncoding.EncodeToString(digest)
	got := strings.TrimSpace(certDigest.FindElement("ds:DigestValue").Text())
	if got != want {
		return fmt.Errorf("xades: check: CertDigest mismatch: got %s, want %s", got, want)
	}
	serial := strings.TrimSpace(iss.FindElement("ds:X509SerialNumber").Text())
	if serial != cert.SerialNumber.String() {
		return fmt.Errorf("xades: check: X509SerialNumber mismatch: got %q, want %q", serial, cert.SerialNumber.String())
	}
	issuer := iss.FindElement("ds:X509IssuerName").Text()
	if issuer != IssuerName(cert) {
		return fmt.Errorf("xades: check: X509IssuerName mismatch: got %q, want %q", issuer, IssuerName(cert))
	}
	return nil
}

// CheckSignedProperties verifies a rendered xades:SignedProperties
// element sp against the signer certificate cert and the signed files
// (in reference order, for signature k), mirroring the
// SignedProperties checks the Estonian e-voting collector applies plus
// its DataObjectFormat invariants:
//
//   - SignaturePolicyIdentifier must be absent (BES/TS profiles);
//   - CheckSigningCertificate passes;
//   - there is exactly one DataObjectFormat per file, i-th with
//     ObjectReference "#<S{k}-RefId{i}>", MimeType equal to the file's
//     media type and MimeType its only child.
func CheckSignedProperties(dm xcrypto.XMLDigestModule, k int, sp *etree.Element, cert *x509.Certificate, files []File) error {
	ssp := sp.FindElement("xades:SignedSignatureProperties")
	if ssp == nil {
		return fmt.Errorf("xades: check: SignedSignatureProperties not found")
	}
	if spi := ssp.FindElement("xades:SignaturePolicyIdentifier"); spi != nil {
		return fmt.Errorf("xades: check: SignaturePolicyIdentifier must be absent (BES/TS profiles)")
	}
	if err := CheckSigningCertificate(dm, ssp, cert); err != nil {
		return err
	}
	dops := sp.FindElement("xades:SignedDataObjectProperties")
	if dops == nil {
		return fmt.Errorf("xades: check: SignedDataObjectProperties not found")
	}
	dofs := dops.FindElements("xades:DataObjectFormat")
	if len(dofs) != len(files) {
		return fmt.Errorf("xades: check: DataObjectFormat count: got %d, want %d", len(dofs), len(files))
	}
	for i, f := range files {
		dof := dofs[i]
		if want := "#" + ReferenceID(k, i); dof.SelectAttrValue("ObjectReference", "") != want {
			return fmt.Errorf("xades: check: DataObjectFormat %d ObjectReference: got %q, want %q", i, dof.SelectAttrValue("ObjectReference", ""), want)
		}
		mt := dof.FindElement("xades:MimeType")
		if mt == nil || mt.Text() != f.MediaType {
			return fmt.Errorf("xades: check: DataObjectFormat %d MimeType: got %v, want %q", i, mt, f.MediaType)
		}
		for _, c := range dof.Child {
			if e, ok := c.(*etree.Element); ok && e.Tag != "MimeType" {
				return fmt.Errorf("xades: check: DataObjectFormat %d contains element %q, want only MimeType", i, e.Tag)
			}
		}
	}
	return nil
}
