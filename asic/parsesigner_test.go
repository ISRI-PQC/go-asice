// ParseSigner key/certificate correspondence and key-block counting
// (companion to TestParseSigner in create_test.go, which covers the
// matching-key success and the single-corrupt-key cases): the parsed
// private key must match the certificate, and the "exactly one
// private key block" contract counts blocks that fail to decode.
package asic

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// TestParseSignerKeyMismatch rejects a well-formed file whose private
// key is not the certificate's key (defect: such a file was accepted
// and produced containers that fail verification everywhere).
func TestParseSignerKeyMismatch(t *testing.T) {
	p := newCreatePKI(t)

	keyPEM := func(t *testing.T, key any) []byte {
		t.Helper()
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal PKCS#8: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	cases := []struct {
		name string
		key  any // a key different from p.Signer.PrivateKey
	}{
		{"same type (ECDSA)", p.Signer2.PrivateKey},
		{"cross type (RSA)", p.Issuer.PrivateKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := append(append([]byte{}, p.Signer.PEM...), keyPEM(t, tc.key)...)
			if _, err := ParseSigner(file); err == nil || !strings.Contains(err.Error(), "does not match the certificate") {
				t.Fatalf("error = %v, want a key/certificate mismatch complaint", err)
			}
		})
	}
}

// TestParseSignerCorruptFirstKeyBlock pins the "exactly one private
// key block" regression: a corrupt first key block used to be dropped
// when a later block parsed, so the file was accepted despite two
// key-typed blocks.
func TestParseSignerCorruptFirstKeyBlock(t *testing.T) {
	p := newCreatePKI(t)
	der, err := x509.MarshalPKCS8PrivateKey(p.Signer.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	file := append(append(append([]byte{}, p.Signer.PEM...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02}})...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	if _, err := ParseSigner(file); err == nil || !strings.Contains(err.Error(), "more than one private key block") {
		t.Fatalf("error = %v, want a two-key-block complaint", err)
	}
}
