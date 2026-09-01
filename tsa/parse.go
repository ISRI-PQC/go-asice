package tsa

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// Parse decodes a DER-encoded TimeStampToken (ContentInfo) and returns
// the structured view used by Check and the HTTP client. The token
// structure is RFC 3161 section 2.4.2: a ContentInfo with content type
// id-signedData wrapping a CMS SignedData whose EncapsulatedContentInfo
// carries the id-ct-TSTInfo content.
//
// Parse performs no trust, freshness, or signature validation — that is
// Validator.Check's job. It does enforce the structural invariants
// the Estonian e-voting collector enforces: the token content type
// must be id-signedData and the EncapsulatedContentInfo content type
// must be id-ct-TSTInfo.
func Parse(der []byte) (*TSToken, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("tsa: unmarshal TimeStampToken: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("tsa: TimeStampToken has %d trailing bytes", len(rest))
	}
	if !ci.ContentType.Equal(OidSignedData) {
		return nil, fmt.Errorf("tsa: TimeStampToken content type is %s, want id-signedData (%s)",
			ci.ContentType, OidSignedData)
	}

	token := &TSToken{
		DER:         append([]byte(nil), der...),
		ContentType: ci.ContentType,
		Content: SignedData{
			Version:          ci.Content.Version,
			DigestAlgorithms: append([]pkix.AlgorithmIdentifier(nil), ci.Content.DigestAlgorithms...),
			EncapContentInfo: TSTContentInfo{
				EContentType: ci.Content.EncapContentInfo.EContentType,
				EContent:     ci.Content.EncapContentInfo.EContent,
			},
		},
	}
	if !token.Content.EncapContentInfo.EContentType.Equal(OidCTTSTInfo) {
		return nil, fmt.Errorf("tsa: token EncapsulatedContentInfo content type is %s, want id-ct-TSTInfo (%s)",
			token.Content.EncapContentInfo.EContentType, OidCTTSTInfo)
	}
	if len(token.Content.EncapContentInfo.EContent) == 0 {
		return nil, fmt.Errorf("tsa: token EncapsulatedContentInfo has no TSTInfo content")
	}

	var info tstInfo
	irest, err := asn1.Unmarshal(token.Content.EncapContentInfo.EContent, &info)
	if err != nil {
		return nil, fmt.Errorf("tsa: unmarshal TSTInfo: %w", err)
	}
	if len(irest) > 0 {
		return nil, fmt.Errorf("tsa: TSTInfo has %d trailing bytes", len(irest))
	}
	token.Content.EncapContentInfo.TSTInfo = &TSTInfo{
		Version:        info.Version,
		Policy:         info.Policy,
		MessageImprint: info.MessageImprint,
		SerialNumber:   info.SerialNumber,
		GenTime:        info.GenTime,
		Accuracy:       Accuracy{Seconds: info.Accuracy.Seconds, Millis: info.Accuracy.Millis, Micros: info.Accuracy.Micros},
		Ordering:       info.Ordering,
		Nonce:          info.Nonce,
		Extensions:     info.Extensions,
	}

	for _, rawCert := range ci.Content.Certificates {
		cert, err := x509.ParseCertificate(rawCert.FullBytes)
		if err != nil {
			// Some in-house TST builders (testutil) wrap each
			// certificate in an extra [0] element; the fixture TST does
			// not. Try the inner TLV.
			if inner := stripOuterTLV(rawCert.FullBytes); inner != nil {
				cert, err = x509.ParseCertificate(inner)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("tsa: parse token certificate: %w", err)
		}
		token.Content.Certificates = append(token.Content.Certificates, cert)
	}

	for _, si := range ci.Content.SignerInfos {
		converted := SignerInfo{
			Version:              si.Version,
			DigestAlgorithm:      si.DigestAlgorithm,
			SignatureAlgorithm:   si.SignatureAlgorithm,
			Signature:            si.Signature,
			SubjectKeyIdentifier: si.SubjectKeyIdentifier,
		}
		if len(si.IssuerAndSerialNumber.Issuer) > 0 {
			converted.IssuerAndSerial = &IssuerSerial{
				Issuer:       si.IssuerAndSerialNumber.Issuer,
				SerialNumber: si.IssuerAndSerialNumber.SerialNumber,
			}
		}
		for _, attr := range si.SignedAttrs {
			converted.SignedAttrs = append(converted.SignedAttrs, SignedAttr{
				AttrType:     attr.AttrType,
				AttrValue:    attr.AttrValue.Bytes,
				attrValueTag: attr.AttrValue.FullBytes[0],
			})
		}
		token.Content.SignerInfos = append(token.Content.SignerInfos, converted)
	}
	return token, nil
}

// findSignerCert selects the certificate in the token's embedded
// Certificates that matches SignerInfo's identifier — issuer + serial
// for version 1, subject key identifier for version 3 — from among
// signers. The configured pool identifies the certificate (the model
// the Estonian e-voting collector's TST validation uses): the token
// must include exactly that certificate.
func findSignerCert(info SignerInfo, signers []*x509.Certificate) (*x509.Certificate, error) {
	switch info.Version {
	case 1:
		if info.IssuerAndSerial == nil {
			return nil, fmt.Errorf("tsa: SignerInfo version 1 without issuer and serial")
		}
		issuer, serial := info.IssuerAndSerial.Issuer, info.IssuerAndSerial.SerialNumber
		for _, c := range signers {
			if certHasIssuerSerial(c, issuer, serial) {
				return c, nil
			}
		}
		return nil, fmt.Errorf("tsa: no configured TSA signer matches issuer %s / serial %s",
			issuer, serial)
	case 3:
		if len(info.SubjectKeyIdentifier) == 0 {
			return nil, fmt.Errorf("tsa: SignerInfo version 3 without subject key identifier")
		}
		for _, c := range signers {
			if len(c.SubjectKeyId) > 0 && equalBytes(c.SubjectKeyId, info.SubjectKeyIdentifier) {
				return c, nil
			}
		}
		return nil, fmt.Errorf("tsa: no configured TSA signer matches subject key identifier")
	default:
		return nil, fmt.Errorf("tsa: unsupported SignerInfo version %d", info.Version)
	}
}

// certHasIssuerSerial reports whether cert was issued by issuer with
// the given serial. Extra names are included in the comparison (the
// Estonian e-voting collector sets Issuer.ExtraNames = Issuer.Names
// before comparing RDN sequences). The comparison is on the DER
// encoding of both RDN sequences.
func certHasIssuerSerial(c *x509.Certificate, issuer pkix.RDNSequence, serial *big.Int) bool {
	c.Issuer.ExtraNames = c.Issuer.Names
	if c.SerialNumber.Cmp(serial) != 0 {
		return false
	}
	got, errA := asn1.Marshal(c.Issuer.ToRDNSequence())
	want, errB := asn1.Marshal(issuer)
	return errA == nil && errB == nil && bytes.Equal(got, want)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stripOuterTLV removes the outer SEQUENCE/[0] tag+length header from a
// DER byte string and returns the inner TLV if it fills the content
// exactly.
func stripOuterTLV(der []byte) []byte {
	if len(der) < 4 || der[0] != 0x30 {
		return nil
	}
	var l int
	off := 0
	switch {
	case der[1] < 0x80:
		l = int(der[1])
		off = 1
	case der[1] == 0x81:
		if len(der) < 3 {
			return nil
		}
		l = int(der[2])
		off = 2
	case der[1] == 0x82:
		if len(der) < 4 {
			return nil
		}
		l = int(der[2])<<8 | int(der[3])
		off = 3
	default:
		return nil
	}
	if len(der) != 1+off+l {
		return nil
	}
	inner := der[1+off:]
	if len(inner) < 2 || inner[0] != 0x30 {
		return nil
	}
	return inner
}
