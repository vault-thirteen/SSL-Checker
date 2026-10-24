package l

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/vault-thirteen/auxie/cio"
	"github.com/vault-thirteen/auxie/errors"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
	cm "github.com/vault-thirteen/SSL-Checker/pkg/models/common"
)

type CRL struct {
	isChecked    bool
	updateTime   time.Time
	rl           *x509.RevocationList
	url          string
	signerCaCert *x509.Certificate

	// This TTL value is a common setting value duplicated in each object for
	// simplicity. This is not any type of a counter.
	ttl time.Duration
}

func NewCRL(url string, isDebugMode bool, crlTtlMinutes uint) (crl *CRL, err error) {
	if isDebugMode {
		cio.PrintMessage(cio.FormatMessage(cm.Msgf_DownloadingCrl, url))
	}

	var crlBytes []byte
	crlBytes, err = h.GetFileFromUrl(url)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(crlBytes)
	if block != nil && block.Type == h.BlockType_CRL {
		crlBytes = block.Bytes
	}

	var rl *x509.RevocationList
	rl, err = x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, err
	}

	timeNow := time.Now()
	if timeNow.Before(rl.ThisUpdate) {
		return nil, errors.ErrorFromText(cm.Err_CrlIsNotYetValid)
	}
	if !rl.NextUpdate.IsZero() && timeNow.After(rl.NextUpdate) {
		return nil, errors.ErrorFromText(cm.Err_CrlHasExpired)
	}

	crl = &CRL{
		rl:           rl,
		url:          url,
		updateTime:   timeNow,
		isChecked:    false,
		signerCaCert: nil,
		ttl:          time.Duration(crlTtlMinutes) * time.Minute,
	}

	return crl, nil
}

// checkSignature performs signature verification against the issuing CA public
// key from the specified list.
func (crl *CRL) checkSignature(caCerts []*x509.Certificate) (err error) {
	for _, caCert := range caCerts {
		if !h.AreEqualPKIXNames(caCert.Subject, crl.rl.Issuer) {
			continue
		}

		if len(crl.rl.AuthorityKeyId) > 0 && len(caCert.SubjectKeyId) > 0 {
			if !bytes.Equal(crl.rl.AuthorityKeyId, caCert.SubjectKeyId) {
				continue
			}
		}

		err = crl.rl.CheckSignatureFrom(caCert)
		if err == nil {
			crl.isChecked = true
			crl.signerCaCert = caCert
			return nil
		}
	}

	return errors.ErrorFromText(cm.Err_IssuerCaCertificateIsNotFound)
}
func (crl *CRL) isActive() bool {
	if !crl.isChecked {
		return false
	}

	timeNow := time.Now()
	if timeNow.After(crl.updateTime.Add(crl.ttl)) {
		return false
	}

	if crl.rl == nil {
		return false
	}

	if len(crl.url) == 0 {
		return false
	}

	if crl.signerCaCert == nil {
		return false
	}

	if crl.ttl == 0 {
		return false
	}

	return true
}
func (crl *CRL) UpdateTime() time.Time {
	return crl.updateTime
}
func (crl *CRL) URL() string {
	return crl.url
}
func (crl *CRL) RevocationList() (rl *x509.RevocationList) {
	if !crl.isActive() {
		return nil
	}

	return crl.rl
}
