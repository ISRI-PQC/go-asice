// In-process RFC 3161 test TSA server. Exported for the acceptance CLI
// tests (PLAN.md Task 9): a production client talks to real TSAs through
// Client; NewTestServer exists so tests can run the full
// request-over-HTTP path against a hermetic token issuer. Test
// infrastructure only — production code must not import it.
package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"
)

// defaultTestServerPolicy matches the SK test TSA policy used by the
// testutil PKI and the external fixtures. Decorative: consumers never
// compare the policy value.
var defaultTestServerPolicy = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}

// supportedImprintAlgorithms is the allowlist of message-imprint hash
// OIDs the test server accepts in a TimeStampReq (the fixture
// generator's own acceptance set, matching the validator's standard
// digest module).
var supportedImprintAlgorithms = map[string]struct{}{
	oidSHA256.String(): {},
	oidSHA384.String(): {},
	oidSHA512.String(): {},
}

// defaultTestServerSerial is the fixed TSTInfo serial of issued tokens
// (a real TSA assigns unique serials; tests do not compare them).
var defaultTestServerSerial = new(big.Int).SetBytes([]byte{81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96})

// CMS signed-attribute OIDs (RFC 5652 section 9 / RFC 5755) as ASN.1
// ObjectIdentifiers (validator.go carries the string forms).
var (
	cmsAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	cmsAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	cmsAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	cmsAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
)

// TestServerOptions configures NewTestServer.
type TestServerOptions struct {
	// Certificate is the TSA certificate embedded in every issued
	// token.
	Certificate *x509.Certificate
	// PrivateKey signs the tokens (ECDSA or RSA).
	PrivateKey crypto.Signer
	// GenTime is the TSTInfo.genTime of every issued token. Required;
	// the zero value is rejected so tests never depend on the wall
	// clock.
	GenTime time.Time
	// Policy is the TSTInfo policy OID (default: the SK test TSA
	// policy).
	Policy asn1.ObjectIdentifier
}

// NewTestServer starts an in-process RFC 3161 HTTP TSA (httptest).
//
// The server TRUSTS the request message imprint — it never sees the
// data itself, so it cannot recompute the digest — and issues a token
// over exactly the imprint in the request. The token mirrors the
// testutil TSTs field by field: SignedData version 3, SHA-256 digest,
// the TSA certificate embedded, and four signed attributes in the
// fixture order (contentType, signingTime, messageDigest, signingCert
// v2), with signingTime equal to GenTime like the fixture.
func NewTestServer(opts TestServerOptions) (*httptest.Server, error) {
	if opts.Certificate == nil {
		return nil, errors.New("tsa: test server: Certificate is required")
	}
	if opts.PrivateKey == nil {
		return nil, errors.New("tsa: test server: PrivateKey is required")
	}
	if opts.GenTime.IsZero() {
		return nil, errors.New("tsa: test server: GenTime is required (no wall-clock default)")
	}
	policy := opts.Policy
	if len(policy) == 0 {
		policy = defaultTestServerPolicy
	}
	var issuerRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(opts.Certificate.RawIssuer, &issuerRDN); err != nil {
		return nil, fmt.Errorf("tsa: test server: TSA issuer name: %w", err)
	}
	s := &testServer{
		cert:      opts.Certificate,
		certDER:   opts.Certificate.Raw,
		certSHA1:  sha1.Sum(opts.Certificate.Raw),
		key:       opts.PrivateKey,
		genTime:   opts.GenTime.UTC(),
		policy:    policy,
		serial:    defaultTestServerSerial,
		issuerRDN: issuerRDN,
	}
	return httptest.NewServer(s), nil
}

type testServer struct {
	cert      *x509.Certificate
	certDER   []byte
	certSHA1  [20]byte
	key       crypto.Signer
	genTime   time.Time
	policy    asn1.ObjectIdentifier
	serial    *big.Int
	issuerRDN pkix.RDNSequence
}

// ServeHTTP answers one RFC 3161 query with a granted response.
func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != ContentTypeQuery {
		http.Error(w, "unexpected content type "+r.Header.Get("Content-Type"), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := ParseTimeStampReq(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, ok := supportedImprintAlgorithms[req.MessageImprint.HashAlgorithm.Algorithm.String()]; !ok {
		http.Error(w, "unsupported message imprint algorithm", http.StatusBadRequest)
		return
	}
	token, err := s.issue(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// TimeStampResp = PKIStatusInfo (status 0 = granted) + token.
	statusDER, err := asn1.Marshal(struct {
		Status int
	}{Status: 0})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentTypeReply)
	if _, err := w.Write(append(statusDER, token...)); err != nil {
		// Response write failure: nothing further to do.
	}
}

// issue builds the token over the request's imprint.
func (s *testServer) issue(req TimeStampReq) ([]byte, error) {
	gen := s.genTime
	info := tstInfo{
		Version:        1,
		Policy:         s.policy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   s.serial,
		GenTime:        gen,
		Nonce:          req.Nonce,
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("marshal TSTInfo: %w", err)
	}

	// The messageDigest attribute covers the exact TSTInfo encoding.
	md := sha256.Sum256(infoDER)
	sc := essSigningCertV2{Certs: []essCertID{{
		CertHash: s.certSHA1[:],
		IssuerAndSerialNumber: essIssuerSerial{
			Issuer:       tsGeneralName{RDN: s.issuerRDN},
			SerialNumber: s.cert.SerialNumber,
		},
	}}}
	attrs := []cmsSignedAttribute{
		{AttrType: cmsAttrContentType, AttrValue: attrSetOf(OidCTTSTInfo)},
		{AttrType: cmsAttrSigningTime, AttrValue: attrSetOf(gen)},
		{AttrType: cmsAttrMessageDigest, AttrValue: attrSetOf(md[:])},
		{AttrType: cmsAttrSigningCert, AttrValue: attrSetOf(sc)},
	}
	attrsDER, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, fmt.Errorf("marshal signed attrs: %w", err)
	}
	attrsDER[0] = 0x31 // CMS: the signed attributes are a SET OF

	sigAlg := oidECDSASHA256
	if _, ok := s.key.(*rsa.PrivateKey); ok {
		sigAlg = oidRSASHA256
	}
	sig, err := signTestToken(s.key, attrsDER)
	if err != nil {
		return nil, err
	}

	null := asn1.RawValue{FullBytes: asn1.NullBytes}
	sd := tsSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256, Parameters: null}},
		EncapContentInfo: tsEncapContentInfo{EContentType: OidCTTSTInfo, EContent: infoDER},
		// FullBytes: the element IS the cert TLV (tag+length included)
		// — the same encoding the testutil TSTs use.
		Certificates: []asn1.RawValue{{FullBytes: s.certDER}},
		SignerInfos: []tsSignerInfo{{
			Version:               1,
			IssuerAndSerialNumber: tsIssuerAndSerial{Issuer: s.issuerRDN, SerialNumber: s.cert.SerialNumber},
			DigestAlgorithm:       pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: null},
			SignedAttrs:           attrs,
			SignatureAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: sigAlg, Parameters: null},
			Signature:             sig,
		}},
	}
	token, err := asn1.Marshal(tsContentInfo{ContentType: OidSignedData, Content: sd})
	if err != nil {
		return nil, fmt.Errorf("marshal token: %w", err)
	}
	return token, nil
}

// signTestToken signs der with SHA-256 (ECDSA ASN.1 DER or RSA
// PKCS#1v15, per key type) — the CMS SignerInfo signature form.
func signTestToken(key crypto.Signer, der []byte) ([]byte, error) {
	sum := sha256.Sum256(der)
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, sum[:])
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	default:
		return nil, fmt.Errorf("tsa: test server: unsupported key type %T", key)
	}
}

// attrSetOf encodes v as one ASN.1 element wrapped in a one-element
// SET (the CMS attribute-value convention).
func attrSetOf(v any) asn1.RawValue {
	inner, err := asn1.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("tsa: test server: marshal attribute value: %v", err))
	}
	return asn1.RawValue{Tag: 17, IsCompound: true, Bytes: inner}
}

// --- marshal-side ASN.1 structures (the parse-side shapes in types.go
// carry RawContent capture fields that must not go out on the wire) ---

// tsContentInfo is a CMS ContentInfo (RFC 5652 section 10.1).
type tsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     tsSignedData `asn1:"explicit,tag:0"`
}

// tsSignedData is a CMS SignedData (RFC 5652 section 5.1).
type tsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo tsEncapContentInfo
	Certificates     []asn1.RawValue `asn1:"set,tag:0,optional"`
	SignerInfos      []tsSignerInfo  `asn1:"set"`
}

type tsEncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,tag:0,optional"`
}

type tsSignerInfo struct {
	Version int

	IssuerAndSerialNumber tsIssuerAndSerial `asn1:"optional"`

	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []cmsSignedAttribute `asn1:"set,tag:0,optional"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type tsIssuerAndSerial struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

// ess shapes (RFC 5755 signingCertificateV2).
type essSigningCertV2 struct {
	Certs []essCertID
}

type essCertID struct {
	CertHash              []byte
	IssuerAndSerialNumber essIssuerSerial `asn1:"optional"`
}

type essIssuerSerial struct {
	Issuer       tsGeneralName
	SerialNumber *big.Int
}

// tsGeneralName is a GeneralName directoryName in [4].
type tsGeneralName struct {
	RDN pkix.RDNSequence `asn1:"explicit,tag:4"`
}
