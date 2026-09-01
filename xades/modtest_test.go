// modtest_test.go — standard crypto module wiring for the xades tests
// (the test default; an alternative backend implements the same
// interfaces).
package xades

import (
	xcrypto "github.com/isri-pqc/xmlsig/crypto"
)

// stdDM returns the standard XML digest module.
func stdDM() xcrypto.XMLDigestModule { return xcrypto.NewStdXMLDigestModule() }
