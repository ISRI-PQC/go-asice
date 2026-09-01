// rdn_escape_test.go — pins the RFC 4514 escaping xades.EncodeRDNSequence
// produces (the byte semantics the interop contract with the Estonian
// e-voting collector pins). These cases guard against a "fix" to the
// replacement template in rdn.go that changes the escaping: in Go's
// regexp expansion a backslash is a plain character, so the template
// `\$1` is backslash + submatch 1 — the correct RFC 4514 escape.
package xades

import (
	"crypto/x509/pkix"
	"testing"
)

func rdnEscapeCN(t *testing.T, value string) string {
	t.Helper()
	dn := pkix.RDNSequence{{pkix.AttributeTypeAndValue{Type: []int{2, 5, 4, 3}, Value: value}}}
	return EncodeRDNSequence(dn)
}

func TestEncodeRDNSequenceEscaping(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Test=CA", "CN=Test\\=CA"}, // '=' anywhere
		{"a;b", "CN=a\\;b"},         // ';' anywhere
		{"a\\", "CN=a\\\\"},         // backslash anywhere
		{" X", "CN=\\ X"},           // leading space
		{"X ", "CN=X\\ "},           // trailing space
		{" X ", "CN=\\ X\\ "},       // leading and trailing space
		{"mid dle", "CN=mid dle"},   // interior space: not escaped
		{"lead#", "CN=lead#"},       // non-leading '#': not escaped
		{"#lead", "CN=\\#lead"},     // leading '#'
		{`a"b`, "CN=a\\\"b"},        // '"' anywhere
		{`a<b`, "CN=a\\<b"},         // '<' anywhere
	}
	for _, tc := range cases {
		if got := rdnEscapeCN(t, tc.in); got != tc.want {
			t.Errorf("EncodeRDNSequence(CN=%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
