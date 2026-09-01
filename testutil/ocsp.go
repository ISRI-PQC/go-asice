package testutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// RFC 6960 OIDs.
var (
	// idPKIXOCSPBasic is the BasicOCSPResponse content type (RFC 6960 4.2.1).
	idPKIXOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

	// oidSHA1 is the CertID hash algorithm: the CertID the Estonian
	// e-voting collector builds for OCSP requests hashes the issuer name
	// with SHA-1 and fills IssuerKeyHash from AuthorityKeyId.
	oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

var asn1Null = asn1.RawValue{Tag: 5}

// The response structures mirror the OCSP response shapes the Estonian
// e-voting collector unmarshals: same field order, tags and optionals,
// so the external acceptance harness parses our responses unchanged.
type ocspCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type ocspSingleResponse struct {
	CertID ocspCertID
	// CertStatus CHOICE; "good" is the empty [0] form (the fixture uses
	// A0 00), which OpenSSL also accepts.
	Status asn1.RawValue
	// `generalized`: OpenSSL's OCSP template expects GeneralizedTime
	// strictly here (Go's default would emit UTCTime below year 2050).
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"explicit,tag:0,optional"`
	SingleExt  []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspResponseData struct {
	// Raw preserves the full tbsResponseData encoding (the bytes the
	// response signature covers).
	Raw               asn1.RawContent
	ResponderIDByName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	// producedAt is ENCODED as GeneralizedTime (the fixture response uses
	// it, and openssl ocsp -respin enforces it — Go's default would emit
	// UTCTime for years below 2050). `generalized` forces it on marshal;
	// unmarshal accepts both forms.
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingleResponse
	ResponseExt []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type basicOCSPResponse struct {
	TBSResponseData    ocspResponseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	// Certs: the optional [0] field with the responder certificate.
	Certs []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type ocspResponseOuter struct {
	ResponseStatus asn1.Enumerated // 0 = successful
	ResponseBytes  responseBytes   `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// certIDForCert builds the CertID the way the Estonian e-voting
// collector builds it: SHA-1 of the RawIssuer DER, the issuer key from
// AuthorityKeyId, and the serial.
// The cert must carry an AuthorityKeyId extension (ours do).
func certIDForCert(cert *Cert) (ocspCertID, error) {
	if len(cert.Certificate.AuthorityKeyId) == 0 {
		return ocspCertID{}, fmt.Errorf("cert %q has no AuthorityKeyId", cert.Certificate.Subject.CommonName)
	}
	nameHash := sha1.Sum(cert.Certificate.RawIssuer)
	return ocspCertID{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidSHA1,
			Parameters: asn1Null,
		},
		IssuerNameHash: nameHash[:],
		IssuerKeyHash:  cert.Certificate.AuthorityKeyId,
		SerialNumber:   cert.Certificate.SerialNumber,
	}, nil
}

// OCSPResponse returns a DER-encoded RFC 6960 "successful" basic OCSP
// response for the PKI's SIGNER cert with status "good", signed by the OCSP
// responder (SHA-256-with-RSA — the collector's OCSP verification
// accepts only the RSA SHA-2/3/4 response-signature variants), with
// producedAt == thisUpdate == the injected time.
//
// Shape, modeled on the fixture response inside testEIDTS.bdoc:
//
//   - ResponderID by name (explicit [1]),
//   - no nextUpdate at the tbs or single level,
//   - no response/single extensions (the fixture's nonce and archive-cutoff
//     extensions are SK-specific and never checked by the collector),
//   - the responder certificate in the optional [0] certs field — the
//     collector's issuer-fallback path finds and verifies the responder
//     from there.
func (p *PKI) OCSPResponse(producedAt time.Time) ([]byte, error) {
	if producedAt.IsZero() {
		return nil, errZeroTime
	}
	producedAt = producedAt.UTC()

	certID, err := certIDForCert(p.Signer)
	if err != nil {
		return nil, err
	}

	tbs := ocspResponseData{
		ResponderIDByName: p.OCSPResponder.Certificate.Subject.ToRDNSequence(),
		ProducedAt:        producedAt,
		Responses: []ocspSingleResponse{{
			CertID: certID,
			// CertStatus "good": the fixture (and OpenSSL's OCSP parser)
			// encode it as context [0], primitive, empty: 80 00.
			Status:     asn1.RawValue{FullBytes: []byte{0x80, 0x00}},
			ThisUpdate: producedAt,
		}},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal tbsResponseData: %w", err)
	}
	sig, err := signDER(p.OCSPResponder.PrivateKey, tbsDER, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign OCSP response: %w", err)
	}

	resp := basicOCSPResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1Null},
		Signature:          asn1.BitString{Bytes: sig},
		// The slice already supplies the CertificateSequence (SEQUENCE OF)
		// layer and the `explicit,tag:0` wraps it; each element must be the
		// raw certificate (which is itself a SEQUENCE) — emitted verbatim
		// via FullBytes so no extra SEQUENCE is added around it.
		Certs: []asn1.RawValue{{FullBytes: p.OCSPResponder.DER}},
	}
	respDER, err := asn1.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal basicOCSPResponse: %w", err)
	}

	outer := ocspResponseOuter{
		ResponseStatus: 0,
		ResponseBytes:  responseBytes{ResponseType: idPKIXOCSPBasic, Response: respDER},
	}
	der, err := asn1.Marshal(outer)
	if err != nil {
		return nil, fmt.Errorf("marshal OCSPResponse: %w", err)
	}
	return der, nil
}

// OCSPStatus reports the parsed status of a "good" response produced at
// wantProducedAt, with checks equivalent to the Estonian e-voting
// collector's: successful status, exactly one singleResponse whose
// certID equals the PKI signer's (the collector's CertID fields),
// responder name matching the PKI responder, signature over the
// tbsResponseData verified with the PKI responder cert, and
// producedAt == thisUpdate == wantProducedAt.
func (p *PKI) OCSPStatus(der []byte, wantProducedAt time.Time) (producedAt time.Time, err error) {
	var outer ocspResponseOuter
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return time.Time{}, fmt.Errorf("unmarshal OCSPResponse: %w", err)
	}
	if len(rest) > 0 {
		return time.Time{}, fmt.Errorf("excess bytes after OCSPResponse: %d", len(rest))
	}
	if int(outer.ResponseStatus) != 0 {
		return time.Time{}, fmt.Errorf("response status %d, want successful(0)", outer.ResponseStatus)
	}
	if !outer.ResponseBytes.ResponseType.Equal(idPKIXOCSPBasic) {
		return time.Time{}, fmt.Errorf("response type %v, want %v", outer.ResponseBytes.ResponseType, idPKIXOCSPBasic)
	}

	var basic basicOCSPResponse
	if rest, err = asn1.Unmarshal(outer.ResponseBytes.Response, &basic); err != nil {
		return time.Time{}, fmt.Errorf("unmarshal basicOCSPResponse: %w", err)
	}
	if len(rest) > 0 {
		return time.Time{}, fmt.Errorf("excess bytes after basicOCSPResponse: %d", len(rest))
	}

	rd := basic.TBSResponseData
	if len(rd.Responses) != 1 {
		return time.Time{}, fmt.Errorf("response has %d singleResponses, want 1", len(rd.Responses))
	}
	want, err := certIDForCert(p.Signer)
	if err != nil {
		return time.Time{}, err
	}
	got := rd.Responses[0].CertID
	if !got.HashAlgorithm.Algorithm.Equal(want.HashAlgorithm.Algorithm) ||
		!bytes.Equal(got.IssuerNameHash, want.IssuerNameHash) ||
		!bytes.Equal(got.IssuerKeyHash, want.IssuerKeyHash) ||
		got.SerialNumber.Cmp(want.SerialNumber) != 0 {
		return time.Time{}, fmt.Errorf("certID mismatch: got {alg %v, name %x, key %x, serial %s}, want {alg %v, name %x, key %x, serial %s}",
			got.HashAlgorithm.Algorithm, got.IssuerNameHash, got.IssuerKeyHash, got.SerialNumber,
			want.HashAlgorithm.Algorithm, want.IssuerNameHash, want.IssuerKeyHash, want.SerialNumber)
	}
	responderRDN := p.OCSPResponder.Certificate.Subject.ToRDNSequence()
	if !rdnEqual(responderRDN, rd.ResponderIDByName) {
		return time.Time{}, fmt.Errorf("responder name %v, want %v", rd.ResponderIDByName, responderRDN)
	}
	if !rd.ProducedAt.Equal(wantProducedAt) || !rd.Responses[0].ThisUpdate.Equal(wantProducedAt) {
		return time.Time{}, fmt.Errorf("times: producedAt %v thisUpdate %v, want %v", rd.ProducedAt, rd.Responses[0].ThisUpdate, wantProducedAt)
	}
	if err := p.OCSPResponder.Certificate.CheckSignature(x509.SHA256WithRSA, rd.Raw, basic.Signature.RightAlign()); err != nil {
		return time.Time{}, fmt.Errorf("response signature: %w", err)
	}
	return rd.ProducedAt, nil
}

// parseOCSPResponseForTest decodes der into the OCSP response structs
// the Estonian e-voting collector unmarshals, so tests can inspect
// individual fields.
func parseOCSPResponseForTest(der []byte) (ocspResponseOuter, basicOCSPResponse, error) {
	var outer ocspResponseOuter
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return outer, basicOCSPResponse{}, err
	}
	var basic basicOCSPResponse
	if _, err := asn1.Unmarshal(outer.ResponseBytes.Response, &basic); err != nil {
		return outer, basic, err
	}
	return outer, basic, nil
}

// signDER hashes der with hash and signs the digest with priv
// (PKCS#1 v1.5 for RSA, r||s for ECDSA).
func signDER(priv crypto.Signer, der []byte, hash crypto.Hash) ([]byte, error) {
	h := hash.New()
	h.Write(der)
	return priv.Sign(rand.Reader, h.Sum(nil), hash)
}

// rdnEqual compares two RDN sequences attribute by attribute (same
// order, type and value) — the match semantics the Estonian e-voting
// collector needs for the responder name comparison.
func rdnEqual(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			av, bv := a[i][j], b[i][j]
			if !av.Type.Equal(bv.Type) || !rdnValueEqual(av.Value, bv.Value) {
				return false
			}
		}
	}
	return true
}

func rdnValueEqual(a, b any) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case []byte:
		bv, ok := b.([]byte)
		return ok && bytes.Equal(av, bv)
	default:
		return fmt.Sprint(a) == fmt.Sprint(b)
	}
}
