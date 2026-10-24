package cm

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/vault-thirteen/auxie/cio"
	"github.com/vault-thirteen/auxie/errors"
	"github.com/vault-thirteen/auxie/file"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
)

type RootCertificatePool struct {
	name       string
	configFile string
	settings   []RootCertificateSetting
	pool       *x509.CertPool
	certs      []*x509.Certificate
}

func NewRootCertificatePool(name string, configFile string, useColours bool, certFileVerificationDelayMs uint) (rcp *RootCertificatePool, err error) {
	rcp = &RootCertificatePool{
		name:       name,
		configFile: configFile,
		settings:   []RootCertificateSetting{},
		pool:       x509.NewCertPool(),
		certs:      []*x509.Certificate{},
	}

	cio.PrintMessage(cio.FormatMessage(Msgf_LoadingRootCertificatePool, name))

	// 1. Read certificate pool settings.
	{
		var buf []byte
		buf, err = file.GetFileContents(rcp.configFile)
		if err != nil {
			return nil, err
		}

		var rawSettings RootCertificateSettingsJson
		decoder := json.NewDecoder(bytes.NewReader(buf))
		decoder.DisallowUnknownFields()
		decoder.UseNumber()

		err = decoder.Decode(&rawSettings)
		if err != nil {
			return nil, err
		}

		if rawSettings.PoolName != rcp.name {
			return nil, errors.ErrorFromFormattedText(Errf_RootCertificatePoolNameMismatch, rcp.configFile)
		}

		var rcs *RootCertificateSetting
		for _, rawSetting := range rawSettings.Keys {
			rcs, err = newRootCertificateSettingFromRawData(rawSetting)
			if err != nil {
				return nil, err
			}

			rcp.settings = append(rcp.settings, *rcs)
		}
	}

	// 2. Fetch certificates and verify them.
	{
		var cert *x509.Certificate
		for _, stn := range rcp.settings {
			cio.Print("    " + stn.URL + " ")

			cert, err = stn.getVerifiedCertificate()
			if err != nil {
				return nil, err
			}

			rcp.pool.AddCert(cert)
			rcp.certs = append(rcp.certs, cert)
			printText(h.CR+" "+Msg_OK+h.LF, useColours, h.AnsiSetColorGreen)

			// Wait to cool down the remote server.
			time.Sleep(time.Duration(certFileVerificationDelayMs) * time.Millisecond)
		}
	}
	cio.PrintMessage()

	return rcp, nil
}
func newRootCertificateSettingFromRawData(rawData RootCertificateSettingJson) (rcs *RootCertificateSetting, err error) {
	rcs = &RootCertificateSetting{
		Name:     rawData.Name,
		KeyType:  rawData.KeyType,
		KeySize:  rawData.KeySize,
		URL:      rawData.URL,
		FilePath: rawData.FilePath,
	}

	rcs.FingerprintSha256, err = parseFingerprintSha256(rawData.FingerprintSha256)
	if err != nil {
		return nil, err
	}

	rcs.TimeValidUntil, err = parseTimeValidUntil(rawData.TimeValidUntil)
	if err != nil {
		return nil, err
	}

	if !rcs.IsValid() {
		return nil, errors.ErrorFromFormattedText(Errf_InvalidCertificateData, rcs.Name)
	}

	return rcs, nil
}
func parseFingerprintSha256(s string) (sha256 [32]byte, err error) {
	s = strings.ToUpper(s)

	if strings.Contains(s, ":") {
		s = strings.Replace(s, ":", "", -1)
	}

	var buf []byte
	buf, err = hex.DecodeString(s)
	if err != nil {
		return sha256, err
	}

	if len(buf) != 32 {
		return sha256, errors.ErrorFromText(Err_InvalidFingerprintSha256)
	}

	copy(sha256[:], buf)

	return sha256, nil
}
func parseTimeValidUntil(s string) (t time.Time, err error) {
	t, err = time.Parse(h.TimeFormat1, s)
	if err == nil {
		return t, nil
	}

	t, err = time.Parse(h.TimeFormat2, s)
	if err == nil {
		return t, nil
	}

	return t, errors.ErrorFromText(Err_UnknownTimeFormat)
}
func printText(msg string, useColours bool, colour string) {
	if !useColours {
		cio.Print(msg)
		return
	}

	msg = colour + msg + h.AnsiSetColorDefault
	cio.Print(msg)
}
func (rcp *RootCertificatePool) Name() string {
	return rcp.name
}
func (rcp *RootCertificatePool) Pool() *x509.CertPool {
	return rcp.pool
}
func (rcp *RootCertificatePool) Certificates() []*x509.Certificate {
	return rcp.certs
}
