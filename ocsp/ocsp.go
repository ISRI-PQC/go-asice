// Package ocsp implements the OCSP client flow behind asice ocsp
// fetch: the RFC 6960 section 4.1.1 CertID of a signer certificate,
// the section 2.2 request wire format, the HTTP exchange, and the
// full-response decode. It exists so a stored (offline) OCSP response
// — the attestation the ASiC-E TS profile embeds — can be fetched
// straight from the responder: signer cert in, full OCSPResponse DER
// out (byte-exact, what create --ocsp-file consumes).
package ocsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	ocspcrypto "github.com/isri-pqc/go-asice/ocsp/crypto"
)

// Response media types (RFC 6960 section 2.2).
const (
	ContentTypeRequest  = "application/ocsp-request"
	ContentTypeResponse = "application/ocsp-response"
)

var (
	// OidOCSPBasic is the id-pkix-OCSPBasic content type of a
	// BasicOCSPResponse (RFC 6960 section 4.2.1).
	OidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// maxResponseSize bounds the OCSP response body (a stored response is
// at most a few KiB; the bound rejects a hostile responder).
const maxResponseSize = 1 << 20

// CertID identifies a certificate the way RFC 6960 section 4.1.1
// defines: the issuer name hash, the issuer key hash, the serial
// number, and the hash algorithm of the two hashes.
type CertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// CertIDForSigner computes the RFC 6960 section 4.1.1 CertID of signer:
// hashAlgorithm SHA-1 (1.3.14.3.2.26), issuerNameHash = SHA-1 of the
// BIT STRING contents of issuer.RawSubject, issuerKeyHash = SHA-1 of
// the BIT STRING contents of issuer.RawSubjectPublicKeyInfo,
// serialNumber = the signer's serial. The digests are computed through
// dm (ADR 0004: the domain performs no direct crypto primitives).
func CertIDForSigner(dm ocspcrypto.DigestModule, signer, issuer *x509.Certificate) (CertID, error) {
	if dm == nil {
		return CertID{}, fmt.Errorf("ocsp: CertIDForSigner requires the crypto modules (DigestModule)")
	}
	if signer == nil || issuer == nil {
		return CertID{}, fmt.Errorf("ocsp: signer and issuer certificates are required")
	}
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return CertID{}, fmt.Errorf("ocsp: issuer SPKI: %w", err)
	}
	digest := dm.GetDigestFunc(oidSHA1)
	nameHash, err := digest(issuer.RawSubject)
	if err != nil {
		return CertID{}, fmt.Errorf("ocsp: issuerNameHash: %w", err)
	}
	keyHash, err := digest(spki.Key.Bytes)
	if err != nil {
		return CertID{}, fmt.Errorf("ocsp: issuerKeyHash: %w", err)
	}
	return CertID{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidSHA1,
			Parameters: asn1.RawValue{FullBytes: asn1.NullBytes},
		},
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		SerialNumber:   signer.SerialNumber,
	}, nil
}

// Request is an OCSPRequest (RFC 6960 section 2.2) for one certificate.
type Request struct {
	CertID CertID
}

type certIDWire struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// requestWire is the RFC 6960 section 2.2 layout: requestList (one
// Request with reqCert only — no singleExt), no requestorName, no
// requestExt.
type requestWire struct {
	RequestList []struct {
		ReqCert certIDWire
	}
}

// Encode serializes the request to DER.
func (r Request) Encode() ([]byte, error) {
	der, err := asn1.Marshal(requestWire{RequestList: []struct {
		ReqCert certIDWire
	}{{ReqCert: certIDWire{
		HashAlgorithm:  r.CertID.HashAlgorithm,
		IssuerNameHash: r.CertID.IssuerNameHash,
		IssuerKeyHash:  r.CertID.IssuerKeyHash,
		SerialNumber:   r.CertID.SerialNumber,
	}}}})
	if err != nil {
		return nil, fmt.Errorf("ocsp: marshal OCSPRequest: %w", err)
	}
	return der, nil
}

// EncodeWrapped serializes the request as the canonical body wrapped in
// one extra SEQUENCE. The reference implementation's responder accepts
// that shape and rejects the bare canonical body (HTTP 400
// "invalid OCSPRequest", observed on its live endpoint); Fetch sends
// the canonical encoding first and falls back to this variant on a 400.
func (r Request) EncodeWrapped() ([]byte, error) {
	inner, err := r.Encode()
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Body asn1.RawValue
	}
	wrap.Body.FullBytes = inner
	der, err := asn1.Marshal(wrap)
	if err != nil {
		return nil, fmt.Errorf("ocsp: marshal wrapped OCSPRequest: %w", err)
	}
	return der, nil
}

// ParseRequest decodes a DER OCSPRequest into its single CertID (the
// shape this package and any conformant request carry).
func ParseRequest(der []byte) (Request, error) {
	var raw requestWire
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return Request{}, fmt.Errorf("ocsp: unmarshal OCSPRequest: %w", err)
	}
	if len(rest) > 0 {
		return Request{}, fmt.Errorf("ocsp: OCSPRequest has %d trailing bytes", len(rest))
	}
	if len(raw.RequestList) != 1 {
		return Request{}, fmt.Errorf("ocsp: OCSPRequest has %d requests, want 1", len(raw.RequestList))
	}
	return Request{CertID: CertID{
		HashAlgorithm:  raw.RequestList[0].ReqCert.HashAlgorithm,
		IssuerNameHash: raw.RequestList[0].ReqCert.IssuerNameHash,
		IssuerKeyHash:  raw.RequestList[0].ReqCert.IssuerKeyHash,
		SerialNumber:   raw.RequestList[0].ReqCert.SerialNumber,
	}}, nil
}

// Basic is the decoded BasicOCSPResponse (RFC 6960 section 4.2.1).
type Basic struct {
	// ResponderName is the response ResponderID name (zero when the
	// response identifies the responder by key hash).
	ResponderName pkix.RDNSequence
	// ProducedAt is the response producedAt.
	ProducedAt time.Time
	// Responses are the singleResponse entries.
	Responses []SingleResponse
	// SignatureAlgorithm and Signature are the response signature over
	// the tbsResponseData.
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	// Certs is the optional [0] field with the responder certificate(s).
	Certs []asn1.RawValue
}

// SingleResponse is one singleResponse (RFC 6960 section 4.2.1).
type SingleResponse struct {
	// CertID is the certified certificate's CertID.
	CertID CertID
	// Status is the CertStatus CHOICE; "good" is the empty [0] form
	// (80 00).
	Status asn1.RawValue
	// ThisUpdate is the singleResponse thisUpdate.
	ThisUpdate time.Time
	// NextUpdate is the singleResponse nextUpdate (zero when absent).
	NextUpdate time.Time
}

// Good reports whether the CertStatus is "good" (the empty [0] form).
func (s SingleResponse) Good() bool {
	return bytes.Equal(s.Status.FullBytes, []byte{0x80, 0x00})
}

// Response is a parsed OCSPResponse (RFC 6960 section 2.3).
type Response struct {
	// Status is the responseStatus value (0 = successful).
	Status int
	// Type is the responseBytes responseType (zero when the response
	// carries no responseBytes).
	Type asn1.ObjectIdentifier
	// Basic is the decoded BasicOCSPResponse (non-nil when the type is
	// id-pkix-OCSPBasic).
	Basic *Basic
}

// StatusName renders the responseStatus (RFC 6960 section 2.3).
func (r *Response) StatusName() string {
	switch r.Status {
	case 0:
		return "successful"
	case 1:
		return "malformedRequest"
	case 2:
		return "internalError"
	case 3:
		return "tryLater"
	case 4:
		return "badTime"
	case 5:
		return "badRequest"
	case 6:
		return "unauthorized"
	}
	return fmt.Sprintf("responseStatus %d", r.Status)
}

// responseWire / basicWire mirror the RFC 6960 OCSP response shapes:
// same field order, tags and optionals as the verify-side decode in
// asic (the stored-response contract).
type responseWire struct {
	ResponseStatus asn1.Enumerated
	ResponseBytes  responseBytesWire `asn1:"explicit,tag:0,optional"`
}

type responseBytesWire struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicWire struct {
	TBSResponseData    responseDataWire
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certs              []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseDataWire struct {
	ResponderIDByName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	ProducedAt        time.Time
	Responses         []singleResponseWire
	ResponseExt       []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponseWire struct {
	CertID     certIDWire
	Status     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time        `asn1:"explicit,tag:0,optional"`
	SingleExt  []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// Parse decodes a full OCSPResponse (the outer status wrapper), and the
// BasicOCSPResponse when the response type is id-pkix-OCSPBasic.
func Parse(der []byte) (*Response, error) {
	var outer responseWire
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("ocsp: unmarshal OCSPResponse: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ocsp: OCSPResponse has %d trailing bytes", len(rest))
	}
	resp := &Response{Status: int(outer.ResponseStatus)}
	if outer.ResponseBytes.ResponseType == nil {
		return resp, nil
	}
	resp.Type = outer.ResponseBytes.ResponseType
	if !resp.Type.Equal(OidOCSPBasic) {
		return resp, nil
	}
	var basic basicWire
	if rest, err := asn1.Unmarshal(outer.ResponseBytes.Response, &basic); err != nil {
		return nil, fmt.Errorf("ocsp: unmarshal BasicOCSPResponse: %w", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("ocsp: BasicOCSPResponse has %d trailing bytes", len(rest))
	}
	b := &Basic{
		ResponderName:      basic.TBSResponseData.ResponderIDByName,
		ProducedAt:         basic.TBSResponseData.ProducedAt,
		SignatureAlgorithm: basic.SignatureAlgorithm,
		Signature:          basic.Signature,
		Certs:              basic.Certs,
	}
	for _, sr := range basic.TBSResponseData.Responses {
		b.Responses = append(b.Responses, SingleResponse{
			CertID: CertID{
				HashAlgorithm:  sr.CertID.HashAlgorithm,
				IssuerNameHash: sr.CertID.IssuerNameHash,
				IssuerKeyHash:  sr.CertID.IssuerKeyHash,
				SerialNumber:   sr.CertID.SerialNumber,
			},
			Status:     sr.Status,
			ThisUpdate: sr.ThisUpdate,
			NextUpdate: sr.NextUpdate,
		})
	}
	resp.Basic = b
	return resp, nil
}

// FetchOptions configures Fetch.
type FetchOptions struct {
	// DigestModule computes the CertID digests (ADR 0004: the domain
	// performs no direct crypto primitives). Required; a zero value is
	// a hard error at Fetch.
	DigestModule ocspcrypto.DigestModule
	// Signer is the attested certificate. Required.
	Signer *x509.Certificate
	// Issuer is the signer's issuer certificate (used to build the
	// CertID). When nil, it is resolved from Chain: the first
	// certificate whose subject matches the signer's issuer name.
	Issuer *x509.Certificate
	// Chain is the certificate pool for Issuer resolution.
	Chain []*x509.Certificate
	// URL is the responder URL. When empty, the signer's AIA
	// id-ad-ocsp entry is used; neither available is an error.
	URL string
	// Timeout bounds the HTTP exchange (0: no client-side timeout).
	Timeout time.Duration
	// HTTPClient is the client used when non-nil (default: a new
	// http.Client bounded by Timeout).
	HTTPClient *http.Client
}

// Fetch POSTs the RFC 6960 OCSP request for Signer to the responder
// (URL, or the signer's AIA when URL is empty) and returns the response:
// the FULL OCSPResponse DER byte-exact as returned — exactly what
// create --ocsp-file consumes — and its decoded form. The response must
// be responseStatus successful (0) with responseType
// id-pkix-OCSPBasic; anything else is an actionable error.
func Fetch(ctx context.Context, opts FetchOptions) ([]byte, *Response, error) {
	if opts.DigestModule == nil {
		return nil, nil, fmt.Errorf("ocsp: Fetch requires the crypto modules (DigestModule)")
	}
	if opts.Signer == nil {
		return nil, nil, fmt.Errorf("ocsp: no signer certificate supplied")
	}
	issuer := opts.Issuer
	if issuer == nil {
		issuer = issuerFromChain(opts.Signer, opts.Chain)
	}
	if issuer == nil {
		return nil, nil, fmt.Errorf("ocsp: no issuer certificate for the signer (pass --issuer or --chain)")
	}
	cid, err := CertIDForSigner(opts.DigestModule, opts.Signer, issuer)
	if err != nil {
		return nil, nil, err
	}
	// Request shapes, in order: the RFC 6960 section 2.2 canonical
	// body, then the same body wrapped in one extra SEQUENCE. The
	// reference implementation's responder accepts the wrapped shape
	// and rejects the canonical body (HTTP 400 "invalid OCSPRequest",
	// observed on its live endpoint), so Fetch tries both.
	reqDER, err := Request{CertID: cid}.Encode()
	if err != nil {
		return nil, nil, err
	}
	wrappedDER, err := Request{CertID: cid}.EncodeWrapped()
	if err != nil {
		return nil, nil, err
	}
	shapes := []struct {
		name string
		der  []byte
	}{
		{"RFC 6960 canonical", reqDER},
		{"wrapped (extra SEQUENCE)", wrappedDER},
	}
	url := opts.URL
	if url == "" {
		url, err = AIAOCSPURL(opts.Signer)
		if err != nil {
			return nil, nil, fmt.Errorf("ocsp: no OCSP responder URL: pass --url or use a cert with an AIA")
		}
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: opts.Timeout}
	}
	var body []byte
	var parsed *Response
	var lastErr error
	for i, shape := range shapes {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(shape.der))
		if err != nil {
			return nil, nil, fmt.Errorf("ocsp: build request: %w", err)
		}
		httpReq.Header.Set("Content-Type", ContentTypeRequest)
		httpResp, err := hc.Do(httpReq)
		if err != nil {
			return nil, nil, fmt.Errorf("ocsp: request %s failed: %w", url, err)
		}
		b, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseSize+1))
		httpResp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("ocsp: read response body: %w", err)
		}
		if len(b) > maxResponseSize {
			return nil, nil, fmt.Errorf("ocsp: response body exceeds %d bytes", maxResponseSize)
		}
		if httpResp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("ocsp: responder %s responded with status %d (%s shape): %s",
				url, httpResp.StatusCode, shape.name, strings.TrimSpace(string(b)))
			// A 400 on the canonical shape is the known responder
			// convention mismatch: retry with the wrapped shape.
			if httpResp.StatusCode == http.StatusBadRequest && i+1 < len(shapes) {
				continue
			}
			return nil, nil, lastErr
		}
		body = b
		parsed, err = Parse(body)
		if err != nil {
			return nil, nil, err
		}
		break
	}
	if parsed == nil {
		return nil, nil, lastErr
	}
	if parsed.Status != 0 {
		return nil, nil, fmt.Errorf("ocsp: responseStatus is %s, want successful", parsed.StatusName())
	}
	if parsed.Type == nil {
		return nil, nil, fmt.Errorf("ocsp: responseStatus is successful but no responseBytes")
	}
	if !parsed.Type.Equal(OidOCSPBasic) {
		return nil, nil, fmt.Errorf("ocsp: responseType is %s, want id-pkix-OCSPBasic (%s)", parsed.Type, OidOCSPBasic)
	}
	return body, parsed, nil
}

// AIAOCSPURL returns the OCSP responder URL of the certificate's AIA
// extension (id-ad-ocsp, 1.3.6.1.5.5.7.48.1.1, the
// uniformResourceIdentifier GeneralName). Go's x509 parser collects the
// id-ad-ocsp GeneralNames into cert.OCSPServer, so that field is the
// source of truth (the AIA entry is not always surfaced in
// cert.Extensions).
func AIAOCSPURL(cert *x509.Certificate) (string, error) {
	if len(cert.OCSPServer) == 0 {
		return "", fmt.Errorf("no id-ad-ocsp AIA entry")
	}
	return cert.OCSPServer[0], nil
}

// issuerFromChain returns the first chain certificate whose subject
// matches the signer's issuer name (the RawSubject DER comparison).
func issuerFromChain(signer *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	for _, c := range chain {
		if bytes.Equal(c.RawSubject, signer.RawIssuer) {
			return c
		}
	}
	return nil
}
