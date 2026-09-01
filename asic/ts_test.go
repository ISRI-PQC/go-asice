// TS-profile rendering unit tests (Task 7): SignTS' structure and input
// guards. The cryptographic acceptance bar (the Estonian e-voting
// collector's Open() in profile TS) is the external acceptance
// harness e2e (maintained outside this repo); here we pin what SignTS
// renders independently of the collector.
package asic

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/isri-pqc/asice/testutil"
)

var tsNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

// tsDocs is the single-file fixture of the SignTS tests.
func tsDocs() []Doc {
	return []Doc{{Name: "test.txt", MediaType: "application/octet-stream", Data: []byte("ts unit data")}}
}

// goodTSData returns TSData whose TimeStamp callback records the
// received data (the canonical ds:SignatureValue bytes) and the produced
// TST, and produces a TST over the received data at tsNow.
func goodTSData(t *testing.T, p *testutil.PKI, received chan []byte, produced chan []byte) (TSData, error) {
	t.Helper()
	ocsp, err := p.OCSPResponse(tsNow)
	if err != nil {
		return TSData{}, err
	}
	return TSData{
		TimeStamp: func(d []byte) ([]byte, error) {
			tst, err := p.TimeStampToken(d, testutil.TSTOptions{GenTime: tsNow})
			if err != nil {
				return nil, err
			}
			if received != nil {
				select {
				case received <- d:
				default:
				}
			}
			if produced != nil {
				select {
				case produced <- tst:
				default:
				}
			}
			return tst, nil
		},
		OCSPResponse: ocsp,
		Certificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	}, nil
}

// TestSignTSRendersUnsignedProperties pins the TS document structure:
// QualifyingProperties carries SignedProperties (unchanged from the BES
// core) plus UnsignedProperties (SignatureTimeStamp S0-T0,
// CertificateValues with the responder and CA certificates,
// RevocationValues/OCSPValues with Id N0); the embedded TST is the
// callback's output; and the callback received exactly one C14N 1.1
// canonical ds:SignatureValue element.
func TestSignTSRendersUnsignedProperties(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: tsNow})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	produced := make(chan []byte, 1)
	ts, err := goodTSData(t, p, received, produced)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := SignTS(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, tsDocs(), tsNow, ts)
	if err != nil {
		t.Fatalf("SignTS: %v", err)
	}
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	qp := d.FindElement("//xades:QualifyingProperties")
	if qp == nil || qp.SelectAttrValue("Target", "") != "#S0" {
		t.Fatalf("QualifyingProperties Target = %v", qp)
	}
	if qp.FindElement("xades:SignedProperties") == nil {
		t.Error("SignedProperties missing from QualifyingProperties")
	}
	usp := qp.FindElement("xades:UnsignedProperties")
	if usp == nil {
		t.Fatal("UnsignedProperties missing from QualifyingProperties")
	}
	uspSP := usp.FindElement("xades:UnsignedSignatureProperties")
	if uspSP == nil {
		t.Fatal("UnsignedSignatureProperties missing")
	}
	st := uspSP.FindElement("xades:SignatureTimeStamp")
	if st == nil || st.SelectAttrValue("Id", "") != "S0-T0" {
		t.Fatalf("SignatureTimeStamp Id = %v", idOf(st))
	}
	et := st.FindElement("xades:EncapsulatedTimeStamp")
	if et == nil {
		t.Fatal("EncapsulatedTimeStamp missing")
	}
	// The embedded TST must be the TST the callback returned (captured
	// below via the TSTData channel).
	embedded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(et.Text()))
	if err != nil {
		t.Fatalf("decode embedded TST: %v", err)
	}
	wantTST := <-produced
	if len(produced) != 0 {
		t.Error("TimeStamp callback called more than once")
	}
	if !bytes.Equal(embedded, wantTST) {
		t.Error("embedded TST is not the TST the callback returned")
	}
	cv := uspSP.FindElement("xades:CertificateValues")
	if cv == nil {
		t.Fatal("CertificateValues missing")
	}
	certs := cv.FindElements("xades:EncapsulatedX509Certificate")
	if len(certs) != 2 {
		t.Fatalf("EmbeddedX509Certificate count: got %d, want 2", len(certs))
	}
	for i, wantID := range []string{"S0-RESPONDER_CERT", "S0-CA-CERT"} {
		if got := certs[i].SelectAttrValue("Id", ""); got != wantID {
			t.Errorf("certificate %d Id: got %q, want %q", i, got, wantID)
		}
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certs[i].Text()))
		if err != nil {
			t.Fatalf("decode certificate %d: %v", i, err)
		}
		var wantDER []byte
		if i == 0 {
			wantDER = p.OCSPResponder.DER
		} else {
			wantDER = p.Issuer.DER
		}
		if string(der) != string(wantDER) {
			t.Errorf("certificate %d DER does not match the supplied certificate", i)
		}
	}
	rv := uspSP.FindElement("xades:RevocationValues")
	if rv == nil {
		t.Fatal("RevocationValues missing")
	}
	ocspEl := rv.FindElement("xades:OCSPValues/xades:EncapsulatedOCSPValue")
	if ocspEl == nil || ocspEl.SelectAttrValue("Id", "") != "N0" {
		t.Fatalf("EncapsulatedOCSPValue Id = %v", idOf(ocspEl))
	}
	ocspDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ocspEl.Text()))
	if err != nil {
		t.Fatalf("decode embedded OCSP: %v", err)
	}
	if string(ocspDER) != string(ts.OCSPResponse) {
		t.Error("embedded OCSP response does not match the supplied one")
	}

	// The callback must have been called exactly once, with the C14N 1.1
	// canonical form of the document's ds:SignatureValue element.
	sv := <-received
	if len(received) != 0 {
		t.Errorf("TimeStamp callback called more than once")
	}
	opening := string(sv[:min(len(sv), 400)])
	if !strings.HasPrefix(string(sv), "<ds:SignatureValue") ||
		!strings.Contains(opening, `Id="S0-SIG"`) ||
		!strings.Contains(opening, `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`) {
		t.Errorf("callback data %q...: want the canonical ds:SignatureValue element with the S0-SIG Id and re-declared in-scope namespaces", opening)
	}

	// The property blocks must live inside ds:Object (they are outside
	// the canonicalized SignedInfo region).
	obj := d.FindElement("//ds:Object")
	if obj == nil || obj.FindElement("xades:QualifyingProperties") == nil {
		t.Error("QualifyingProperties must be the content of ds:Object")
	}
}

// TestSignTSIndex pins the S{k} identifier scheme for k > 0: the TST,
// OCSP, and certificate Ids derive from k.
func TestSignTSIndex(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: tsNow})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	ts, err := goodTSData(t, p, received, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := SignTS(2, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, tsDocs(), tsNow, ts)
	if err != nil {
		t.Fatalf("SignTS(2): %v", err)
	}
	s := string(doc)
	for _, want := range []string{`<ds:Signature Id="S2">`, `<ds:SignatureValue Id="S2-SIG">`,
		`<xades:SignatureTimeStamp Id="S2-T0">`, `<xades:EncapsulatedX509Certificate Id="S2-RESPONDER_CERT">`,
		`<xades:EncapsulatedX509Certificate Id="S2-CA-CERT">`, `<xades:EncapsulatedOCSPValue Id="N2">`} {
		if !strings.Contains(s, want) {
			t.Errorf("document missing %s", want)
		}
	}
	sv := <-received
	opening := string(sv[:min(len(sv), 400)])
	if !strings.HasPrefix(string(sv), "<ds:SignatureValue") || !strings.Contains(opening, `Id="S2-SIG"`) {
		t.Errorf("callback data: want S2-SIG canonical element, got %q...", opening)
	}
}

// TestSignTSGuards pins the input guards and error propagation.
func TestSignTSGuards(t *testing.T) {
	p, err := testutil.NewPKI(testutil.Options{Now: tsNow})
	if err != nil {
		t.Fatal(err)
	}
	ocsp, err := p.OCSPResponse(tsNow)
	if err != nil {
		t.Fatal(err)
	}
	base := TSData{
		TimeStamp:    func(d []byte) ([]byte, error) { return p.TimeStampToken(d, testutil.TSTOptions{GenTime: tsNow}) },
		OCSPResponse: ocsp,
		Certificates: []*x509.Certificate{p.OCSPResponder.Certificate, p.Issuer.Certificate},
	}
	docs := tsDocs()

	if _, err := SignTS(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, tsNow, base); err != nil {
		// (positive control: the good input must succeed)
		t.Fatalf("good TSData must sign: %v", err)
	}
	cases := []struct {
		name string
		ts   TSData
	}{
		{"nil TimeStamp", TSData{OCSPResponse: ocsp, Certificates: base.Certificates}},
		{"empty OCSP", TSData{TimeStamp: base.TimeStamp, Certificates: base.Certificates}},
		{"no certificates", TSData{TimeStamp: base.TimeStamp, OCSPResponse: ocsp}},
		{"one certificate", TSData{TimeStamp: base.TimeStamp, OCSPResponse: ocsp, Certificates: base.Certificates[:1]}},
		{"three certificates", TSData{TimeStamp: base.TimeStamp, OCSPResponse: ocsp, Certificates: append(append([]*x509.Certificate{}, base.Certificates...), p.Root.Certificate)}},
		{"nil certificate DER", TSData{TimeStamp: base.TimeStamp, OCSPResponse: ocsp, Certificates: []*x509.Certificate{p.OCSPResponder.Certificate, nil}}},
	}
	for _, c := range cases {
		if _, err := SignTS(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, tsNow, c.ts); err == nil {
			t.Errorf("%s: expected error, got none", c.name)
		}
	}
	if _, err := SignTS(-1, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, tsNow, base); err == nil {
		t.Error("SignTS(-1, ...) must fail")
	}
	if _, err := SignTS(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, nil, tsNow, base); err == nil {
		t.Error("SignTS with no docs must fail")
	}
	// TimeStamp errors must propagate wrapped.
	errTSA := errors.New("TSA unavailable")
	bad := base
	bad.TimeStamp = func(d []byte) ([]byte, error) { return nil, errTSA }
	if _, err := SignTS(0, stdSignerModule(t, p.Signer.PrivateKey), stdDigestModule(), p.Signer.Certificate, docs, tsNow, bad); !errors.Is(err, errTSA) {
		t.Errorf("TimeStamp error propagation: %v", err)
	}
}
