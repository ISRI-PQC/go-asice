package xades

import "testing"

func TestIDScheme(t *testing.T) {
	tests := []struct {
		got  string
		want string
	}{
		{SignatureID(0), "S0"},
		{SignatureID(1), "S1"},
		{ReferenceID(0, 0), "S0-RefId0"},
		{ReferenceID(0, 5), "S0-RefId5"},
		{ReferenceID(1, 0), "S1-RefId0"},
		{SignatureValueID(0), "S0-SIG"},
		{SignatureValueID(1), "S1-SIG"},
		{SignedPropertiesID(0), "S0-SignedProperties"},
		{SignedPropertiesID(2), "S2-SignedProperties"},
		{SignedPropertiesURI(0), "#S0-SignedProperties"},
		{TimestampID(0), "S0-T0"},
		{ResponderCertificateID(0), "S0-RESPONDER_CERT"},
		{ResponderCertificateID(1), "S1-RESPONDER_CERT"},
		{CACertificateID(0), "S0-CA-CERT"},
		{OCSPValueID(0), "N0"},
		{OCSPValueID(1), "N1"},
	}
	for i, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("test %d: got %q, want %q", i, tc.got, tc.want)
		}
	}
}
