package h

import (
	"testing"

	"github.com/vault-thirteen/auxie/tester"
)

func Test_GetSystemRootCertificates(t *testing.T) {
	aTest := tester.New(t)

	caCerts, err := GetSystemRootCertificates()
	aTest.MustBeNoError(err)
	aTest.MustBeEqual(len(caCerts) > 0, true)
}
