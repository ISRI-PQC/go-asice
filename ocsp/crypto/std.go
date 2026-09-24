package crypto

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ErrUnsupportedDigestAlgorithm is returned by the standard digest
// module for a hash algorithm OID it does not support.
var ErrUnsupportedDigestAlgorithm = errors.New("ocsp: unsupported digest algorithm")

// standardDigestModule is the standard (Go crypto library) DigestModule.
type standardDigestModule struct{}

var _ DigestModule = (*standardDigestModule)(nil)

// NewStdDigestModule returns the standard digest module. It supports
// SHA-1 — the hash algorithm RFC 6960 fixes for the CertID.
func NewStdDigestModule() DigestModule {
	return &standardDigestModule{}
}

// digestAlgorithms maps the hash algorithm OIDs the standard
// implementation supports.
var digestAlgorithms = map[string]crypto.Hash{
	"1.3.14.3.2.26": crypto.SHA1, // the RFC 6960 CertID hash
}

func (s standardDigestModule) GetDigestFunc(algo asn1.ObjectIdentifier) func(input []byte) ([]byte, error) {
	return func(input []byte) ([]byte, error) {
		h, ok := digestAlgorithms[algo.String()]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedDigestAlgorithm, algo)
		}
		hh := h.New()
		hh.Write(input)
		return hh.Sum(nil), nil
	}
}
