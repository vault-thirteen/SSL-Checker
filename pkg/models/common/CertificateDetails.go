package cm

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/vault-thirteen/auxie/cio"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
)

const (
	CertificateDetailsFormat = "Certificate" + h.CRLF +
		// Subject.
		h.Tab + "Subject" + h.CRLF +
		h.Tab2 + "Organisation: %s" + h.CRLF +
		h.Tab2 + "Name (CN): %s" + h.CRLF +
		h.Tab2 + "Country: %s" + h.CRLF +
		h.Tab2 + "Postal Code: %s" + h.CRLF +
		h.Tab2 + "Address: %s" + h.CRLF +

		// Issuer.
		h.Tab + "Issuer" + h.CRLF +
		h.Tab2 + "Name (CN): %s" + h.CRLF +
		h.Tab2 + "Country: %s" + h.CRLF +
		h.Tab2 + "Organisation: %s" + h.CRLF +

		// Other data.
		h.Tab + "Valid Time" + h.CRLF +
		h.Tab2 + "Start: %s" + h.CRLF +
		h.Tab2 + "End: %s" + h.CRLF +
		h.Tab + "Version: %d" + h.CRLF +
		h.Tab + "Serial Number: %v" + h.CRLF +
		h.Tab + "Key Type: %s" + h.CRLF +
		h.Tab + "Key Size: %d" + h.CRLF +

		// Other arrays.
		h.Tab + "OCSP Server: %s" + h.CRLF +
		h.Tab + "Issuing Certificate URL: %s" + h.CRLF +
		h.Tab + "DNS Names: %s" + h.CRLF +
		h.Tab + "Email Addresses: %s" + h.CRLF +
		h.Tab + "IP Addresses: %s" + h.CRLF +
		h.Tab + "URIs: %s" + h.CRLF +
		h.Tab + "CRL Distribution Points: %s" + h.CRLF
)

type CertificateDetails struct {
	Version      int
	SerialNumber *big.Int
	Issuer       pkix.Name
	Subject      pkix.Name
	TimeStart    time.Time
	TimeEnd      time.Time

	OCSPServer            []string
	IssuingCertificateURL []string

	DnsNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	CRLDistributionPoints []string
	KeyType               KeyType
	KeySize               int
}

func NewCertificateDetails(cert *x509.Certificate) (cd *CertificateDetails, err error) {
	if cert == nil {
		return nil, errors.New(Err_NullPointer)
	}

	cd = &CertificateDetails{
		Issuer:       cert.Issuer,
		Subject:      cert.Subject,
		TimeStart:    cert.NotBefore,
		TimeEnd:      cert.NotAfter,
		Version:      cert.Version,
		SerialNumber: cert.SerialNumber,

		OCSPServer:            cert.OCSPServer,
		IssuingCertificateURL: cert.IssuingCertificateURL,
		DnsNames:              cert.DNSNames,
		EmailAddresses:        cert.EmailAddresses,

		IPAddresses: cert.IPAddresses,
		URIs:        cert.URIs,

		CRLDistributionPoints: cert.CRLDistributionPoints,
		KeyType:               KeyType(cert.PublicKeyAlgorithm),
	}

	cd.KeySize, err = h.GetCertificateKeySize(cert)
	if err != nil {
		return nil, err
	}

	return cd, nil
}
func (cd *CertificateDetails) Print() {
	msg := cio.FormatMessage(CertificateDetailsFormat,
		// Subject.
		cd.Subject.Organization,
		cd.Subject.CommonName,
		cd.Subject.Country,
		h.FormatStringsArray(cd.Subject.PostalCode),
		h.FormatStringsArray(cd.Subject.StreetAddress),

		// Issuer.
		cd.Issuer.CommonName,
		h.FormatStringsArray(cd.Issuer.Country),
		h.FormatStringsArray(cd.Issuer.Organization),

		// Other data.
		cd.TimeStart,
		cd.TimeEnd,
		cd.Version,
		cd.SerialNumber,
		cd.KeyType.ToString(),
		cd.KeySize,

		// Other arrays.
		h.FormatStringsArray(cd.OCSPServer),
		h.FormatStringsArray(cd.IssuingCertificateURL),
		h.FormatStringsArray(cd.DnsNames),
		h.FormatStringsArray(cd.EmailAddresses),
		h.FormatStringsArray(h.IPAddressesAsStrings(cd.IPAddresses)),
		h.FormatStringsArray(h.UrlsAsStrings(cd.URIs)),
		h.FormatStringsArray(cd.CRLDistributionPoints),
	)

	cio.PrintMessage(msg)
}
