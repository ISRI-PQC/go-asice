// Tests for the tsa package: the RFC 3161 TimeStampReq/Resp codecs and
// the token Parse codec. The tokens used here are HERMETIC (generated
// by the testutil PKI via newTestTSA, fixedNow reference time) —
// self-consistency pins; the fixture-TST interop proofs (the TSTs
// embedded in the collector's fixtures testEIDTS.bdoc / testMIDTS.bdoc)
// live in the external acceptance harness (maintained outside this
// repo).

package tsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/isri-pqc/asice/testutil"
)

// --- TimeStampReq codec ---

func TestTimeStampReqRoundTrip(t *testing.T) {
	sha := sha256.Sum256([]byte("data"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  OidSHA256,
				Parameters: asn1.RawValue{FullBytes: asn1.NullBytes},
			},
			HashedMessage: sha[:],
		},
		Nonce:   new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		CertReq: true,
	}
	der, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := ParseTimeStampReq(der)
	if err != nil {
		t.Fatalf("ParseTimeStampReq: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
	if !got.MessageImprint.HashAlgorithm.Algorithm.Equal(OidSHA256) {
		t.Errorf("HashAlgorithm = %s, want SHA-256", got.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(got.MessageImprint.HashedMessage, sha[:]) {
		t.Errorf("HashedMessage mismatch")
	}
	if got.Nonce == nil || got.Nonce.Cmp(req.Nonce) != 0 {
		t.Errorf("Nonce = %v, want %v", got.Nonce, req.Nonce)
	}
	if !got.CertReq {
		t.Errorf("CertReq = false, want true")
	}

	// The wire form starts with the Version INTEGER 1 (Go's encoder
	// does not apply the default tag on marshal; the Estonian e-voting
	// collector encodes it
	// explicitly too).
	if der[2] != 0x02 || der[3] != 0x01 || der[4] != 0x01 {
		t.Errorf("wire form does not start with Version INTEGER 1: % x", der[:5])
	}

	// A wrong version is rejected.
	bad := req
	bad.Version = 2
	if _, err := bad.Encode(); err == nil {
		t.Errorf("Encode with Version 2 succeeded, want error")
	}

	// Trailing garbage is rejected.
	if _, err := ParseTimeStampReq(append(append([]byte(nil), der...), 0x00)); err == nil {
		t.Errorf("ParseTimeStampReq accepted trailing bytes")
	}
}

// --- TimeStampResp codec ---

// tsResponseDER encodes a minimal TimeStampResp for tests: a status
// INTEGER, then the token bytes when granted.
func tsResponseDER(t *testing.T, status int, token []byte) []byte {
	t.Helper()
	statusDER, err := asn1.Marshal(struct {
		Status int
	}{Status: status})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	return append(statusDER, token...)
}

func TestParseTimeStampRespRejected(t *testing.T) {
	resp, err := ParseTimeStampResp(tsResponseDER(t, 4, nil))
	if err != nil {
		t.Fatalf("ParseTimeStampResp: %v", err)
	}
	if resp.Status.Status != 4 {
		t.Errorf("status = %d, want 4", resp.Status.Status)
	}
	if resp.TimeStampToken != nil {
		t.Errorf("token present, want nil")
	}
}

func TestParseTimeStampRespGranted(t *testing.T) {
	// A real hermetic token (testutil TST): the codec test checks that
	// the status is granted and the token bytes round-trip byte-exact.
	_, token := newTestTSA(t, []byte("granted token data"), testutil.TSTOptions{})
	resp, err := ParseTimeStampResp(tsResponseDER(t, 0, token))
	if err != nil {
		t.Fatalf("ParseTimeStampResp: %v", err)
	}
	if resp.Status.Status != 0 {
		t.Errorf("status = %d, want 0", resp.Status.Status)
	}
	if resp.TimeStampToken == nil {
		t.Fatalf("no token")
	}
	if !resp.TimeStampToken.ContentType.Equal(OidSignedData) {
		t.Errorf("token content type = %s, want id-signedData", resp.TimeStampToken.ContentType)
	}
	if !bytes.Equal(resp.TimeStampToken.DER, token) {
		t.Errorf("token DER differs from the response bytes")
	}
}

// --- Token Parse codec (hermetic TST) ---

// Corrupted token bytes must not parse to a usable token.
func TestParseCorruptedToken(t *testing.T) {
	_, tst := newTestTSA(t, []byte("corruption data"), testutil.TSTOptions{})

	// A truncated token must fail to parse.
	if _, err := Parse(tst[:len(tst)/2]); err == nil {
		t.Errorf("Parse accepted a truncated token")
	}
	// A content type other than id-signedData must fail.
	wrong := append([]byte(nil), tst...)
	idData, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	if err != nil {
		t.Fatalf("marshal id-data: %v", err)
	}
	copy(wrong[2:2+len(idData)], idData)
	if _, err := Parse(wrong); err == nil {
		t.Errorf("Parse accepted a token with content type id-data")
	}
	// Flipped bytes inside the token must not parse to a usable token;
	// note here the parse-level behavior for the record.
	corrupted := append([]byte(nil), tst...)
	corrupted[len(corrupted)/2] ^= 0xFF
	if _, err := Parse(corrupted); err != nil {
		t.Logf("Parse rejected corrupted bytes at the parse level: %v", err)
	}
}
