// modtest_test.go — standard crypto module wiring for the asic tests
// (the test default; an alternative backend implements the same
// interfaces).
package asic

import (
	"crypto"
	"testing"

	asiccrypto "github.com/isri-pqc/go-asice/asic/crypto"
	xcrypto "github.com/isri-pqc/go-xmlsig/crypto"
)

// stdSignerModule wraps a private key in the standard ASiC-E signer
// module (SHA-256, the domain's signature hash).
func stdSignerModule(t *testing.T, key crypto.Signer) xcrypto.XMLSignatureSignerModule {
	t.Helper()
	sm, err := asiccrypto.NewStdSignerModule(key, crypto.SHA256)
	if err != nil {
		t.Fatalf("NewStdSignerModule: %v", err)
	}
	return sm
}

// stdDigestModule returns the standard XML digest module.
func stdDigestModule() xcrypto.XMLDigestModule {
	return xcrypto.NewStdXMLDigestModule()
}

// stdVerifyOptions returns a VerifyOptions with the standard crypto
// modules wired (the test default).
func stdVerifyOptions(profile Profile) VerifyOptions {
	return VerifyOptions{
		Profile:        profile,
		DigestModule:   stdDigestModule(),
		VerifierModule: asiccrypto.NewStdVerifierModule(),
		ChainModule:    asiccrypto.NewStdCertificateChainModule(),
		OCSPModule:     asiccrypto.NewStdOCSPVerifierModule(),
	}
}

// besVerifyOptions returns a BES-profile VerifyOptions over the
// standard modules.
func besVerifyOptions(rootsPEM, interPEM []byte) VerifyOptions {
	o := stdVerifyOptions(ProfileBES)
	o.RootsPEM = rootsPEM
	o.IntermediatesPEM = interPEM
	return o
}
