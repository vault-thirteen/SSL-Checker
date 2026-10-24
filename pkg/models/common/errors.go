package cm

import (
	"crypto/x509"

	"github.com/vault-thirteen/auxie/errors"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
)

const (
	Err_SettingsFileIsNotSpecified    = "settings file is not specified"
	Err_NullPointer                   = "null pointer"
	Err_UnknownTimeFormat             = "unknown time format"
	Err_CertificateIsOutdated         = "certificate is outdated"
	Err_InvalidFingerprintSha256      = "invalid SHA256 fingerprint"
	Err_BadAddress                    = "bad address"
	Err_NoCertificates                = "no certificates are found"
	Err_CertificateParseError         = "certificate parse error"
	Err_CertificateCountMismatch      = "certificate count mismatch"
	Err_ColourIsNotSet                = "colour is not set"
	Err_NotActive                     = "not active"
	Err_Anomaly                       = "anomaly"
	Err_CrlIsNotYetValid              = "CRL is not yet valid"
	Err_CrlHasExpired                 = "CRL has expired"
	Err_IssuerCaCertificateIsNotFound = "issuer CA certificate is not found"

	Errf_RootCertificatePoolNameMismatch = "root certificate pool name mismatch, file: %s"
	Errf_MismatchInAlgorithm             = "algorithm mismatch: %s"
	Errf_MismatchInKeySize               = "mismatch in key size: %s"
	Errf_MismatchInFingerprint           = "fingerprint mismatch: %s"
	Errf_MismatchInTimeEnd               = "mismatch in valid time (end): %s"
	Errf_InvalidCertificateData          = "invalid certificate data, name: %s"
	Errf_PoolIsNotFound                  = "pool is not found, idx: %d"
	Errf_CertificateWasRevocated         = "certificate was revocated, reasonCode: %d, time: %s"
)

func Error_RevocatedCertificate(revocationDetails *x509.RevocationListEntry) (err error) {
	return errors.ErrorFromFormattedText(Errf_CertificateWasRevocated, revocationDetails.ReasonCode, revocationDetails.RevocationTime.Format(h.TimeFormat1))
}
