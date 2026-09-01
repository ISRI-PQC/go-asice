package testutil

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// RFC 3161 / CMS OIDs.
var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCTTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// defaultTSTPolicy is the policy OID of the SK test TSA — exactly
	// 0.4.0.2023.1.1 as embedded in the testEIDTS.bdoc fixture. It is
	// decorative: the collector's TST checks never compare the policy value.
	defaultTSTPolicy = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
)

var defaultTSTSerial = new(big.Int).SetBytes([]byte{81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96})

// TSTOptions configures the time-stamp token.
type TSTOptions struct {
	// GenTime is REQUIRED and becomes both TSTInfo.genTime and the
	// signingTime signed attribute — identical, like the fixture. The
	// collector requires signingTime-genTime to fall in [0, tsp
	// DelayTime]; the trust YAMLs leave DelayTime at 0, so the two
	// must be equal.
	GenTime time.Time

	// Serial is the TSTInfo serial number (default: a fixed 16-byte value).
	Serial *big.Int

	// Nonce is included in TSTInfo only when non-nil. The fixture carries
	// a 21-byte nonce; the collector checks the nonce only when the
	// caller supplies one, and the bdoc flow never does.
	Nonce *big.Int

	// Policy is the TSTInfo policy OID (default: defaultTSTPolicy).
	Policy asn1.ObjectIdentifier
}

// tstInfo is RFC 3161 TimeStampToken's content type
// (https://tools.ietf.org/html/rfc3161#section-2.4.2), the same shape
// the collector unmarshals.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tstMessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       tstAccuracy      `asn1:"optional"`
	Ordering       bool             `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	Extensions     []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type tstAccuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

type tstMessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// CMS SignedData structures (RFC 5652), same shapes the collector
// unmarshals.
type timeStpToken struct {
	ContentType asn1.ObjectIdentifier
	Content     signedData `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"set,tag:0,optional"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0,optional"`
}

type cmsSignerInfo struct {
	Version               int
	IssuerAndSerialNumber issuerAndSerialNumber `asn1:"optional"`
	SubjectKeyIdentifier  []byte                `asn1:"tag:0,optional"`
	DigestAlgorithm       pkix.AlgorithmIdentifier
	SignedAttrs           []cmsSignedAttribute `asn1:"set,tag:0,optional"`
	SignatureAlgorithm    pkix.AlgorithmIdentifier
	Signature             []byte
	UnsignedAttrs         []pkix.AttributeTypeAndValue `asn1:"set,tag:1,optional"`
}

type issuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

type cmsSignedAttribute struct {
	AttrType  asn1.ObjectIdentifier
	AttrValue asn1.RawValue // SET OF with one value (tag 0x31)
}

// signingCertificate (RFC 5652 §9 / RFC 5755 ess) for the signingCert
// attribute.
type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	HashAlgorithm         pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash              []byte
	IssuerAndSerialNumber issuerSerial `asn1:"optional"`
}

// issuerSerial is the RFC 5755 IssuerSerial: a GeneralName
// directoryName in [4] and the serial number. The GeneralName element
// itself carries the [4] tag (0xa4); wrapping it in an extra SEQUENCE
// produces a shape neither the fixture TST nor the Estonian e-voting
// collector's parser accepts (it expects the GeneralName element to
// carry the explicit [4] tag with the directoryName RDN sequence).
type issuerSerial struct {
	Issuer       generalName
	SerialNumber *big.Int
}

type generalName struct {
	RDN pkix.RDNSequence `asn1:"explicit,tag:4"`
}

// TimeStampToken returns a DER-encoded RFC 3161 TimeStampToken over the
// SHA-256 imprint of data, signed by the PKI's TSA. The structure mirrors
// the TST embedded in testEIDTS.bdoc field by field:
//
//	ContentInfo { id-signedData, [0] SignedData }
//	  SignedData version 3 (the Estonian e-voting
//	                        collector enforces 3 — non id-data content
//	                        type)
//	    digestAlgorithms { sha256 }          (fixture: { sha512 }; the
//	                                          collector ignores the content)
//	    encapContentInfo id-ct-TSTInfo, [0] TSTInfo DER
//	    certificates [0] { TSA cert }        (the collector requires the
//	                                          signer cert to be present)
//	    signerInfos: one SignerInfo version 1 (issuer+serial of the TSA
//	      cert); digestAlg sha256 (fixture: sha512); signed attrs in the
//	      fixture order —
//	        contentType   -> id-ct-TSTInfo
//	        signingTime   -> GenTime          (fixture: == genTime)
//	        messageDigest -> SHA-256(TSTInfo DER)
//	        signingCert   -> v2 { essCertIDv2 { SHA-1(TSA cert),
//	                        issuerSerial[4] { TSA issuer name, serial } } }
//	      sigAlg ecdsa-with-SHA256 (fixture: sha512WithRSA; both are in
//	      the collector's accepted signature-algorithm set)
//	TSTInfo: version 1, policy defaultTSTPolicy (= the fixture's OID),
//	  imprint sha256, serial (TSTOptions.Serial), genTime GenTime, nonce
//	  only when given (the fixture has one), no accuracy/ordering/
//	  extensions (fixture: none).
func (p *PKI) TimeStampToken(data []byte, opts TSTOptions) ([]byte, error) {
	if opts.GenTime.IsZero() {
		return nil, errZeroTime
	}
	gentime := opts.GenTime.UTC()
	serial := opts.Serial
	if serial == nil {
		serial = defaultTSTSerial
	}
	policy := opts.Policy
	if len(policy) == 0 {
		policy = defaultTSTPolicy
	}

	// TSTInfo first: the messageDigest signed attribute covers its exact
	// encoding, like every RFC 3161 TSA.
	dataHash := sha256.Sum256(data)
	info := tstInfo{
		Version: 1,
		Policy:  policy,
		MessageImprint: tstMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1Null},
			HashedMessage: dataHash[:],
		},
		SerialNumber: serial,
		GenTime:      gentime,
		Nonce:        opts.Nonce,
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("marshal TSTInfo: %w", err)
	}

	// Signed attributes, in the fixture's order, each value a one-element
	// SET. Go's asn1 preserves slice order (no SET OF sorting).
	attrs := []cmsSignedAttribute{
		{AttrType: oidAttrContentType, AttrValue: attrSetOf(oidCTTSTInfo)},
		{AttrType: oidAttrSigningTime, AttrValue: attrSetOf(gentime)},
	}
	md := sha256.Sum256(infoDER)
	attrs = append(attrs,
		cmsSignedAttribute{AttrType: oidAttrMessageDigest, AttrValue: attrSetOf(md[:])},
	)

	// signingCert attribute: v2 with the TSA cert id (SHA-1 hash, like the
	// fixture) and its issuer/serial.
	tsa := p.TSA
	tsaIssuerRDN := tsa.Certificate.RawIssuer // raw DER of the issuer name
	var issuerRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(tsaIssuerRDN, &issuerRDN); err != nil {
		return nil, fmt.Errorf("TSA issuer name: %w", err)
	}
	sha1hash := sha1.Sum(tsa.DER)
	ess := essCertIDv2{
		CertHash: sha1hash[:],
		IssuerAndSerialNumber: issuerSerial{
			Issuer:       generalName{RDN: issuerRDN},
			SerialNumber: tsa.Certificate.SerialNumber,
		},
	}
	sc := signingCertificateV2{Certs: []essCertIDv2{ess}}
	attrs = append(attrs, cmsSignedAttribute{AttrType: oidAttrSigningCert, AttrValue: attrSetOf(sc)})

	// Sign over the signed attrs: CMS encodes them as SET OF (tag 0x31);
	// Go marshals the slice as SEQUENCE OF, so patch the tag exactly as
	// the collector's TST signature check reconstructs it.
	attrsDER, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, fmt.Errorf("marshal signed attrs: %w", err)
	}
	attrsDER[0] = 0x31 // SET OF
	sig, err := signDER(p.TSA.PrivateKey, attrsDER, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign TST: %w", err)
	}

	sha256Alg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1Null}
	sd := signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{sha256Alg},
		EncapContentInfo: encapsulatedContentInfo{
			EContentType: oidCTTSTInfo,
			EContent:     infoDER,
		},
		// FullBytes: the element IS the cert TLV (tag+length included);
		// Tag:16+Bytes would add an extra SEQUENCE around it, which the
		// collector's inclusion check (bytes.Equal(cert.Raw,
		// RawContent)) rejects — same fix as the OCSP Certs field
		// (ocsp.go).
		Certificates: []asn1.RawValue{{FullBytes: tsa.DER}},
		SignerInfos: []cmsSignerInfo{{
			Version:               1,
			IssuerAndSerialNumber: issuerAndSerialNumber{Issuer: issuerRDN, SerialNumber: tsa.Certificate.SerialNumber},
			DigestAlgorithm:       sha256Alg,
			SignedAttrs:           attrs,
			SignatureAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256, Parameters: asn1Null},
			Signature:             sig,
		}},
	}
	token := timeStpToken{ContentType: oidSignedData, Content: sd}
	der, err := asn1.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal TimeStampToken: %w", err)
	}
	return der, nil
}

// attrSetOf encodes value as one ASN.1 element and wraps it in a
// one-element SET (the CMS attribute-value convention the Estonian
// e-voting collector enforces: "the attribute value be a SET with a
// single entry").
// attrSetOf encodes value as a one-element SET OF (tag 0x31): the CMS
// attribute-value convention (RFC 5652), and exactly what the fixture's
// signed attributes carry.
func attrSetOf(v any) asn1.RawValue {
	inner, err := asn1.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("testutil: marshal attribute value: %v", err))
	}
	return asn1.RawValue{Tag: 17, IsCompound: true, Bytes: inner}
}
