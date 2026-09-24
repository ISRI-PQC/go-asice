package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// The Akamu PKI models a NON-SK certificate hierarchy — the shape that
// breaks the collector's certID check. Its issuer CA's SubjectKeyId is
// NOT SHA-1 of its SPKI key value (it is SHA-256, 32 bytes), so the
// signer leaf's AuthorityKeyId (32 bytes, copied from the issuer SKI)
// differs from the RFC 6960 issuerKeyHash (SHA-1 of the issuer SPKI key
// value, 20 bytes). The hermetic NewPKI models the SK test PKI (SKI =
// SHA-1(SPKI)), where the two values coincide and the go-asice certID
// bug is invisible; this PKI exposes it.
//
// The OCSP responder is the issuer CA itself (CA-as-responder shape, no
// embedded responder certificate — the Akamu shape), signing the OCSP
// response with EC P-256 (the Akamu responder shape).

var (
	akamuSerialRoot   = new(big.Int).SetBytes([]byte{0xa1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	akamuSerialIssuer = new(big.Int).SetBytes([]byte{0xb1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	akamuSerialSigner = new(big.Int).SetBytes([]byte{0xc1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	akamuSerialTSA    = new(big.Int).SetBytes([]byte{0xd1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
)

// NewAkamuPKI generates a fresh non-SK test PKI (EC P-256 throughout)
// per Options. The issuer CA's SubjectKeyId is SHA-256 of its SPKI key
// value (not SHA-1), so the signer's AuthorityKeyId differs from the
// RFC 6960 issuerKeyHash. The issuer CA doubles as the OCSP responder
// (CA-as-responder shape, no embedded certificates).
func NewAkamuPKI(opts Options) (*PKI, error) {
	if opts.Now.IsZero() {
		return nil, errZeroTime
	}
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = opts.Now.Add(-24 * time.Hour)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = opts.Now.Add(defaultValidity)
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("testutil: NotAfter %s must be after NotBefore %s", notAfter, notBefore)
	}

	name := func(cn string) pkix.Name {
		return pkix.Name{
			Country:      []string{"EE"},
			Organization: []string{"ASICE Test Solutions AS"},
			CommonName:   cn,
		}
	}
	ecKey := func() (*ecdsa.PrivateKey, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	rootKey, err := ecKey()
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	issuerKey, err := ecKey()
	if err != nil {
		return nil, fmt.Errorf("generate issuer key: %w", err)
	}
	signerKey, err := ecKey()
	if err != nil {
		return nil, fmt.Errorf("generate signer key: %w", err)
	}
	tsaKey, err := ecKey()
	if err != nil {
		return nil, fmt.Errorf("generate TSA key: %w", err)
	}

	// root: self-signed CA. Non-SK convention: SKI = SHA-256(SPKI).
	rootTmpl := &x509.Certificate{
		SerialNumber:          akamuSerialRoot,
		Subject:               name("AKAMU of ASICE Root CA"),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          subjectKeyIDSHA256(rootKey.Public()),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootTmpl.AuthorityKeyId = rootTmpl.SubjectKeyId // self-signed
	root, err := signCert(rootTmpl, rootTmpl, rootKey.Public(), rootKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}

	// issuer: CA signed by the root. The non-SK property: SKI =
	// SHA-256(SPKI), so the signer's AKI differs from SHA-1(SPKI).
	issuerTmpl := &x509.Certificate{
		SerialNumber:          akamuSerialIssuer,
		Subject:               name("AKAMU of ASICE Issuer CA"),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          subjectKeyIDSHA256(issuerKey.Public()),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuer, err := signCert(issuerTmpl, root.Certificate, issuerKey.Public(), rootKey, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}

	// signer leaf: ECDSA, critical KU ContentCommitment (required by the
	// collector); its AuthorityKeyId is the issuer SKI (SHA-256, 32 bytes),
	// copied automatically by x509.CreateCertificate.
	signerTmpl := &x509.Certificate{
		SerialNumber:          akamuSerialSigner,
		Subject:               name("AKAMU of ASICE EID2025"),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}
	signer, err := signCert(signerTmpl, issuer.Certificate, signerKey.Public(), issuerKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}

	// TSA leaf: ECDSA, EKU TimeStamping (like the hermetic PKI TSA).
	tsaTmpl := &x509.Certificate{
		SerialNumber:          akamuSerialTSA,
		Subject:               name("AKAMU of ASICE TSA"),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidEKUTimeStamping},
		BasicConstraintsValid: true,
	}
	tsa, err := signCert(tsaTmpl, root.Certificate, tsaKey.Public(), rootKey, tsaKey)
	if err != nil {
		return nil, fmt.Errorf("tsa: %w", err)
	}

	// CA-as-responder: the issuer CA is the OCSP responder.
	return &PKI{Root: root, Issuer: issuer, Signer: signer, OCSPResponder: issuer, TSA: tsa}, nil
}

// subjectKeyIDSHA256 is the SHA-256 of the public key BIT STRING contents
// (a non-SK key identifier — deliberately different from subjectKeyID's
// SHA-1). The 32-byte result guarantees the signer's AuthorityKeyId differs
// from the RFC 6960 20-byte issuerKeyHash.
func subjectKeyIDSHA256(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(fmt.Sprintf("testutil: marshal public key: %v", err))
	}
	key, err := spkiKeyBytes(der)
	if err != nil {
		panic(fmt.Sprintf("testutil: decode public key: %v", err))
	}
	h := sha256.Sum256(key)
	return h[:]
}

// spkiKeyBytes returns the contents of the BIT STRING field of a
// SubjectPublicKeyInfo DER (the RFC 6960 "value field of the
// subjectPublicKeyInfo" the issuerKeyHash is taken over).
func spkiKeyBytes(spkiDER []byte) ([]byte, error) {
	var spki struct {
		Alg pkix.AlgorithmIdentifier
		Key asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, err
	}
	return spki.Key.Bytes, nil
}

// OCSPResponseRFC6960 returns a DER-encoded RFC 6960 "successful" basic
// OCSP response for the signer cert using the RFC 6960 CertID:
// issuerNameHash = SHA-1(issuer subject DER), issuerKeyHash =
// SHA-1(issuer SPKI key value) — NOT the signer's AuthorityKeyId — SHA-1
// hash algorithm, the signer's serial. The response is signed by the
// responder (CA-as-responder, the Akamu shape) and embeds NO responder
// certificate. producedAt == thisUpdate == the injected time.
func OCSPResponseRFC6960(responder, signer, issuer *Cert, producedAt time.Time) ([]byte, error) {
	if producedAt.IsZero() {
		return nil, errZeroTime
	}
	producedAt = producedAt.UTC()

	nameHash := sha1.Sum(signer.Certificate.RawIssuer)
	issuerKey, err := spkiKeyBytes(issuer.Certificate.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("decode issuer SubjectPublicKeyInfo: %w", err)
	}
	keyHash := sha1.Sum(issuerKey)
	cid := ocspCertID{
		HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1Null},
		IssuerNameHash: nameHash[:],
		IssuerKeyHash:  keyHash[:],
		SerialNumber:   signer.Certificate.SerialNumber,
	}

	tbs := ocspResponseData{
		ResponderIDByName: responder.Certificate.Subject.ToRDNSequence(),
		ProducedAt:        producedAt,
		Responses: []ocspSingleResponse{{
			CertID: cid,
			// CertStatus "good": the empty context [0] form (80 00) of RFC 6960 2.3.
			Status:     asn1.RawValue{FullBytes: []byte{0x80, 0x00}},
			ThisUpdate: producedAt,
		}},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("marshal tbsResponseData: %w", err)
	}
	// The responder (the issuer CA) is EC P-256; the response signature is
	// an ecdsa-with-SHA256 DER sequence (the Akamu responder shape).
	sig, err := signDER(responder.PrivateKey, tbsDER, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign OCSP response: %w", err)
	}

	resp := basicOCSPResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256, Parameters: asn1Null},
		Signature:          asn1.BitString{Bytes: sig},
		// No embedded responder certificate (CA-as-responder shape).
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
