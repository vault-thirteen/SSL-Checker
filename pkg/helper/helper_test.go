package h

import (
	"testing"

	"github.com/vault-thirteen/auxie/tester"
)

func Test_ValidateDomainAndPort(t *testing.T) {
	aTest := tester.New(t)

	s := "example.org"

	// Test #1. Zero or negative port number.
	aTest.MustBeAnError(ValidateDomainAndPort(&s, -1))

	// Test #2. Too big port number.
	aTest.MustBeAnError(ValidateDomainAndPort(&s, 66000))

	// Test #3. Invalid character in domain.
	s = "golang!org"
	aTest.MustBeAnError(ValidateDomainAndPort(&s, 443))

	// Test #4. Normal full URL instead of a domain.
	s = "https://example.org/abc?q=123"
	aTest.MustBeNoError(ValidateDomainAndPort(&s, 443))
	aTest.MustBeEqual(s, "example.org")

	// Test #5. Fake full URL instead of a domain.
	s = "ftp://example.org/qwerty"
	aTest.MustBeAnError(ValidateDomainAndPort(&s, 443))

	// Test #6. Normal data.
	s = "microsoft.com"
	aTest.MustBeNoError(ValidateDomainAndPort(&s, 443))
	aTest.MustBeEqual(s, "microsoft.com")
}
