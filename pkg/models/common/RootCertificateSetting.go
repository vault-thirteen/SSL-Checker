package cm

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/vault-thirteen/auxie/errors"
	"github.com/vault-thirteen/auxie/file"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
)

type RootCertificateSetting struct {
	Name              string
	KeyType           KeyType
	KeySize           int
	FingerprintSha256 [32]byte
	TimeValidUntil    time.Time
	URL               string
	FilePath          string
}

func (rcs RootCertificateSetting) IsValid() bool {
	if (len(strings.TrimSpace(rcs.Name)) == 0) ||
		(!rcs.KeyType.IsValid()) ||
		(rcs.KeySize == 0) ||
		(rcs.TimeValidUntil.IsZero()) ||
		(len(strings.TrimSpace(rcs.URL)) == 0) ||
		(len(strings.TrimSpace(rcs.FilePath)) == 0) {
		return false
	}

	return true
}
func (rcs RootCertificateSetting) getVerifiedCertificate() (cert *x509.Certificate, err error) {
	// 1. Check time.
	timeNow := time.Now()
	if timeNow.After(rcs.TimeValidUntil) {
		return nil, errors.ErrorFromText(Err_CertificateIsOutdated)
	}

	// 2. Read local certificate file and check its parameters.
	var localCert *x509.Certificate
	{
		var buf []byte
		buf, err = file.GetFileContents(rcs.FilePath)
		if err != nil {
			return nil, err
		}
		localCert, err = parseCertificateBytes(buf)
		if err != nil {
			return nil, err
		}
		if localCert == nil {
			return nil, errors.ErrorFromText(Err_NullPointer)
		}

		var localKeySize int
		localKeySize, err = h.GetCertificateKeySize(localCert)
		if err != nil {
			return nil, err
		}

		localFingerprint := sha256.Sum256(localCert.Raw)

		err = rcs.compareCertParameters(rcs.FilePath, localCert.PublicKeyAlgorithm, localKeySize, localFingerprint, localCert.NotAfter)
		if err != nil {
			return nil, err
		}
	}

	// 3. Read remote certificate file and check its parameters.
	var remoteCert *x509.Certificate
	{
		remoteCert, err = fetchAndParseCertificate(rcs.URL)
		if err != nil {
			return nil, err
		}
		if remoteCert == nil {
			return nil, errors.ErrorFromText(Err_NullPointer)
		}

		var remoteKeySize int
		remoteKeySize, err = h.GetCertificateKeySize(remoteCert)
		if err != nil {
			return nil, err
		}

		remoteFingerprint := sha256.Sum256(remoteCert.Raw)

		err = rcs.compareCertParameters(rcs.URL, remoteCert.PublicKeyAlgorithm, remoteKeySize, remoteFingerprint, remoteCert.NotAfter)
		if err != nil {
			return nil, err
		}
	}

	return localCert, nil
}
func (rcs RootCertificateSetting) compareCertParameters(source string, keyType x509.PublicKeyAlgorithm, keySize int, fingerprint [32]byte, timeEnd time.Time) (err error) {
	// Key type (algorithm).
	if keyType != x509.PublicKeyAlgorithm(rcs.KeyType) {
		return errors.ErrorFromFormattedText(Errf_MismatchInAlgorithm, source)
	}

	// Key size.
	if keySize != rcs.KeySize {
		return errors.ErrorFromFormattedText(Errf_MismatchInKeySize, source)
	}

	// Fingerprint.
	if !bytes.Equal(fingerprint[:], rcs.FingerprintSha256[:]) {
		return errors.ErrorFromFormattedText(Errf_MismatchInFingerprint, source)
	}

	// End of valid time.
	if roundTimeToDay(timeEnd) != roundTimeToDay(rcs.TimeValidUntil) {
		return errors.ErrorFromFormattedText(Errf_MismatchInTimeEnd, source)
	}

	return err
}
func roundTimeToDay(in time.Time) (out time.Time) {
	return in.UTC().Truncate(h.TimeDay)
}
func fetchAndParseCertificate(certUrl string) (cert *x509.Certificate, err error) {
	var data []byte
	data, err = h.GetFileFromUrl(certUrl)
	if err != nil {
		return nil, err
	}

	cert, err = parseCertificateBytes(data)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
func parseCertificateBytes(data []byte) (cert *x509.Certificate, err error) {
	derBytes := getDerBytes(data)

	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
func getDerBytes(data []byte) (derData []byte) {
	// Try decoding the certificate using PEM format.
	// If it fails, we assume, it is using DER encoding.
	block, _ := pem.Decode(data)
	if block != nil && block.Type == h.BlockType_Certificate {
		return block.Bytes
	}

	return data
}
