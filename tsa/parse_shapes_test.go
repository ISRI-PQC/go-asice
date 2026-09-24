// Wire-shape coverage of ParseTimeStampResp (the three accepted
// shapes, byte-exact token handling, and the rejection paths) plus the
// policy-carried TSDelayTime extraction.
package tsa

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/isri-pqc/go-asice/testutil"
)

var parseShapesT = time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)

// newParseShapeFixture builds a real hermetic token (testutil PKI) and
// the granted status block for the shape tests.
func newParseShapeFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	p, err := testutil.NewPKI(testutil.Options{Now: parseShapesT})
	if err != nil {
		t.Fatal(err)
	}
	token, err := p.TimeStampToken([]byte("shape data"), testutil.TSTOptions{GenTime: parseShapesT})
	if err != nil {
		t.Fatal(err)
	}
	status, err := asn1.Marshal(struct {
		Status int
	}{Status: 0})
	if err != nil {
		t.Fatal(err)
	}
	return token, status
}

// contentOf returns the content octets of a DER element (the header
// stripped).
func contentOf(t *testing.T, der []byte) []byte {
	t.Helper()
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes
}

// outerSeq wraps content in a universal SEQUENCE TLV.
func outerSeq(content []byte) []byte {
	out := []byte{0x30}
	out = append(out, derLength(len(content))...)
	return append(out, content...)
}

func TestParseTimeStampRespShapes(t *testing.T) {
	token, status := newParseShapeFixture(t)

	// Canonical children: the [0] EXPLICIT status wrapper (0xA0, the
	// content IS the status SEQUENCE TLV), and the token in its three
	// accepted forms: the constructed [16] context form (0xB0 — the
	// [16] IMPLICIT ContentInfo), the primitive [16] OCTET STRING
	// (0x90 — wrapping the full ContentInfo TLV), and the raw
	// ContentInfo (0x30).
	statusExplicit := append([]byte{0xA0, byte(len(status))}, status...)
	statusExplicit = append([]byte{0xA0}, derLength(len(status))...)
	statusExplicit = append(statusExplicit, status...)
	tokenImplicit := append(append([]byte{0xB0}, derLength(len(contentOf(t, token)))...), contentOf(t, token)...)
	tokenOctet := append(append([]byte{0x90}, derLength(len(token))...), token...)

	cases := []struct {
		name  string
		body  []byte
		noTok bool
	}{
		{"flat granted", append(status, token...), false},
		{"wrapped granted", outerSeq(append(status, token...)), false},
		{"wrapped status-only", outerSeq(status), true},
		{"canonical implicit token", outerSeq(append(statusExplicit, tokenImplicit...)), false},
		{"canonical octet token", outerSeq(append(statusExplicit, tokenOctet...)), false},
		{"canonical raw token", outerSeq(append(statusExplicit, token...)), false},
		{"canonical status-only", outerSeq(statusExplicit), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := ParseTimeStampResp(tc.body)
			if err != nil {
				t.Fatalf("ParseTimeStampResp: %v", err)
			}
			if resp.Status.Status != 0 {
				t.Errorf("status = %d, want 0", resp.Status.Status)
			}
			if tc.noTok {
				if resp.TimeStampToken != nil {
					t.Errorf("token present, want none")
				}
				return
			}
			if resp.TimeStampToken == nil {
				t.Fatal("token missing, want present")
			}
			// Byte-exact: the token is the input token (the [16] form is
			// re-sequenced to the ContentInfo tag — identical bytes for
			// a DER-canonical input token).
			if !bytes.Equal(resp.TimeStampToken.DER, token) {
				t.Errorf("token DER differs from the input token")
			}
			if !resp.TimeStampToken.ContentType.Equal(OidSignedData) {
				t.Errorf("content type = %s, want id-signedData", resp.TimeStampToken.ContentType)
			}
		})
	}
}

func TestParseTimeStampRespStatusFields(t *testing.T) {
	// A status block with statusString and failInfo (the PKIStatusInfo
	// [1]/[2] fields) in the canonical shape.
	status := struct {
		Status       int
		StatusString []string       `asn1:"optional,tag:1"`
		FailInfo     asn1.BitString `asn1:"optional,tag:2"`
	}{Status: 4, StatusString: []string{"rejected: badAlg"}, FailInfo: asn1.BitString{Bytes: []byte{0x80}}}
	statusDER, err := asn1.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	body := outerSeq(append(append([]byte{0xA0}, derLength(len(statusDER))...), statusDER...))
	resp, err := ParseTimeStampResp(body)
	if err != nil {
		t.Fatalf("ParseTimeStampResp: %v", err)
	}
	if resp.Status.Status != 4 || len(resp.Status.StatusString) != 1 || resp.Status.StatusString[0] != "rejected: badAlg" {
		t.Errorf("status = %+v, want 4 with statusString", resp.Status)
	}
	if len(resp.Status.FailInfo.Bytes) != 1 || resp.Status.FailInfo.Bytes[0] != 0x80 {
		t.Errorf("failInfo = % x, want the rejected bit", resp.Status.FailInfo.Bytes)
	}
}

func TestParseTimeStampRespUnrecognizable(t *testing.T) {
	token, status := newParseShapeFixture(t)
	// The token as an APPLICATION-class [16] element (0x70): neither
	// the canonical context form nor a ContentInfo.
	tokenApp := append(append([]byte{0x70}, derLength(len(contentOf(t, token)))...), contentOf(t, token)...)
	statusExplicit := append(append([]byte{0xA0}, derLength(len(status))...), status...)

	cases := []struct {
		name string
		body []byte
	}{
		{"not a SEQUENCE", asn1Integer(t, 1)},
		{"three children", outerSeq(append(append(status, token...), status...))},
		{"application-class token child", outerSeq(append(statusExplicit, tokenApp...))},
		{"second child not a SEQUENCE", outerSeq(append(status, []byte{0x05, 0x00}...))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseTimeStampResp(tc.body); err == nil {
				t.Error("ParseTimeStampResp accepted an unrecognizable body")
			}
		})
	}
}

func asn1Integer(t *testing.T, v int) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestTSDelayFromToken(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: parseShapesT})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("delay data")

	// No extension: no bound.
	tok, err := p.TimeStampToken(data, testutil.TSTOptions{GenTime: parseShapesT})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := TSDelayFromToken(tok); ok {
		t.Error("no extension: bound reported, want none")
	}

	// The policy-parameter extension (extnOID == policy OID, INTEGER
	// seconds): the bound is carried by the TST's TSA policy.
	policy := asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
	secs, err := asn1.Marshal(90)
	if err != nil {
		t.Fatal(err)
	}
	tok, err = p.TimeStampToken(data, testutil.TSTOptions{
		GenTime:    parseShapesT,
		Policy:     policy,
		Extensions: []pkix.Extension{{Id: policy, Value: secs}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := TSDelayFromToken(tok)
	if !ok || bound != 90*time.Second {
		t.Errorf("bound = %v (ok=%v), want 90s", bound, ok)
	}

	// A foreign extension OID (a different policy's parameter) is
	// ignored.
	other, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	tok, err = p.TimeStampToken(data, testutil.TSTOptions{
		GenTime:    parseShapesT,
		Policy:     policy,
		Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: other}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := TSDelayFromToken(tok); ok {
		t.Error("foreign extension: bound reported, want none")
	}
}
