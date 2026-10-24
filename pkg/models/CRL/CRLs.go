package l

import (
	"crypto/x509"

	"github.com/vault-thirteen/auxie/errors"

	cm "github.com/vault-thirteen/SSL-Checker/pkg/models/common"
)

type CRLs struct {
	isDebugMode   bool
	crlTtlMinutes uint
	byURL         map[string]*CRL
}

func NewCRLs(isDebugMode bool, crlTtlMinutes uint) (crls *CRLs, err error) {
	crls = &CRLs{
		isDebugMode:   isDebugMode,
		crlTtlMinutes: crlTtlMinutes,
		byURL:         make(map[string]*CRL),
	}

	return crls, nil
}
func (crls *CRLs) GetActiveCRL(listURL string, caCerts []*x509.Certificate) (crl *CRL, err error) {
	crl = crls.getCRL(listURL)
	if crl != nil {
		return crl, nil
	}

	err = crls.addCRL(listURL, caCerts)
	if err != nil {
		return nil, err
	}

	crl = crls.getCRL(listURL)
	if crl == nil {
		// Anomaly may happen if program becomes extremely slow or hangs up.
		// While CRLs may be expired, time is critical for us, and we can not
		// allow any error here. Certificates and their CRLs are a security
		// mechanism which must work without any error. For most software
		// programmers on this planet, such punctuality is a strange thing,
		// but not for us.
		return nil, errors.ErrorFromText(cm.Err_Anomaly)
	}

	return crl, nil
}
func (crls *CRLs) getCRL(listURL string) (crl *CRL) {
	var ok bool
	crl, ok = crls.byURL[listURL]
	if !ok {
		return nil
	}

	if !crl.isActive() {
		return nil
	}

	return crl
}
func (crls *CRLs) addCRL(listURL string, caCerts []*x509.Certificate) (err error) {
	var crl *CRL
	crl, err = NewCRL(listURL, crls.isDebugMode, crls.crlTtlMinutes)
	if err != nil {
		return err
	}

	err = crl.checkSignature(caCerts)
	if err != nil {
		return err
	}

	if !crl.isActive() {
		return errors.ErrorFromText(cm.Err_NotActive)
	}

	crls.byURL[listURL] = crl

	return nil
}
