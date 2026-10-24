package h

import (
	"bufio"
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vault-thirteen/auxie/cio"
	"github.com/vault-thirteen/auxie/errors"

	chkm "github.com/vault-thirteen/SSL-Checker/pkg/models/tool/checker/keyboard"
)

const (
	CR             = "\r"
	LF             = "\n"
	CRLF           = CR + LF
	Tab            = "\t"
	Tab2           = Tab + Tab
	Tab3           = Tab + Tab + Tab
	HostPortFormat = "%s:%d"
	TimeFormat1    = "2006-01-02"
	TimeFormat2    = time.RFC3339
	TimeDay        = time.Hour * 24
	NetworkType    = "tcp"
	DefaultPort    = 443
)

const (
	BlockType_Certificate = "CERTIFICATE"
	BlockType_CRL         = "X509 CRL"
)

const (
	AnsiSetColorRed     = "\033[0;31m"
	AnsiSetColorYellow  = "\033[0;33m"
	AnsiSetColorGreen   = "\033[0;32m"
	AnsiSetColorDefault = "\033[0;0m"
)

const (
	ExitCode_GenericError = 1
)

func FormatHostPort(host string, port uint16) string {
	return cio.FormatMessage(HostPortFormat, host, port)
}
func ValidateDomainAndPort(x *string, port int) (err error) {
	// Check for imbeciles.
	if port <= 0 {
		return errors.ErrorFromText(Err_InvalidPortNumber)
	}

	// Check for out-of-range port number values.
	portU16 := uint16(port)
	if int(portU16) != port {
		return errors.ErrorFromText(Err_InvalidPortNumber)
	}

	if x == nil {
		return errors.ErrorFromText(Err_InvalidDomain)
	}
	*x = strings.ToLower(*x)

	var u *url.URL
	u, err = url.Parse(*x)
	if err != nil {
		return err
	}

	if u.Scheme == "https" {
		*x = u.Hostname()
	}

	// N.B.: Allowed symbols in domains: a-z, A-Z, 0-9, dot and hyphen.
	for _, r := range *x {
		if ('a' <= r) && (r <= 'z') {
			continue
		}
		if ('0' <= r) && (r <= '9') {
			continue
		}
		if (r == '.') || (r == '-') {
			continue
		}

		return errors.ErrorFromText(Err_InvalidDomain)
	}

	address := FormatHostPort(*x, portU16)

	// To overcome the bug in Go language, we need to write shit code ...
	address = "https://" + address

	u, err = url.Parse(address)
	if err != nil {
		return err
	}

	if u.Scheme != "https" {
		return errors.ErrorFromText(Err_InvalidDomain)
	}

	if u.Hostname() != *x {
		return errors.ErrorFromText(Err_InvalidDomain)
	}

	portU16S := strconv.FormatUint(uint64(port), 10)
	if u.Port() != portU16S {
		return errors.ErrorFromText(Err_InvalidPortNumber)
	}

	// Such a paranoidal check is performed here due to lack of respect to
	// developers of Go language. For more information, see the following bug
	// report:
	//
	// net/url: URL parser is broken. #82393
	// https://github.com/golang/go/issues/82393

	return nil
}
func FormatStringsArray(sa []string) string {
	var sb strings.Builder

	sb.WriteString("[")

	iMax := len(sa) - 1
	for i, s := range sa {
		if i < iMax {
			sb.WriteString(`"` + s + `",`)
		} else {
			sb.WriteString(`"` + s + `"`)
		}
	}

	sb.WriteString("]")

	return sb.String()
}
func UrlsAsStrings(urls []*url.URL) (out []string) {
	out = make([]string, 0, len(urls))

	for _, u := range urls {
		if u == nil {
			continue
		}

		out = append(out, u.String())
	}

	return out
}
func IPAddressesAsStrings(ipas []net.IP) (out []string) {
	out = make([]string, 0, len(ipas))

	for _, ipa := range ipas {
		out = append(out, ipa.String())
	}

	return out
}
func GetCertificateKeySize(cert *x509.Certificate) (keySize int, err error) {
	if cert == nil {
		return -1, errors.ErrorFromText(Err_NullPointer)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey: // RSA.
		return pub.N.BitLen(), nil

	case *dsa.PublicKey: // DSA.
		return pub.P.BitLen(), nil

	case *ecdsa.PublicKey: // ECDSA.
		return pub.Curve.Params().BitSize, nil

	case ed25519.PublicKey: // Ed25519.
		return ed25519.PublicKeySize * 8, nil

	default:
		return 0, errors.ErrorFromFormattedText(Errf_UnsupportedKeyType, cert.PublicKey)
	}
}
func AreEqualPKIXNames(n1, n2 pkix.Name) bool {
	b1, err1 := asn1.Marshal(n1.ToRDNSequence())
	if err1 != nil {
		return false
	}

	b2, err2 := asn1.Marshal(n2.ToRDNSequence())
	if err2 != nil {
		return false
	}

	return bytes.Equal(b1, b2)
}
func IsCertificateRevocated(cert *x509.Certificate, crl *x509.RevocationList) (isRevocated bool, entry *x509.RevocationListEntry) {
	for _, rce := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(rce.SerialNumber) == 0 {
			return true, &rce
		}
	}
	return false, nil
}
func GetInputKey(isDebugMode bool) (key cio.Key, err error) {
	if !isDebugMode {
		return cio.GetInputKey()
	}

	// Emulate keys for stupid environments.
	{
		var r rune
		reader := bufio.NewReader(os.Stdin)
		r, _, err = reader.ReadRune()
		if err != nil {
			return cio.Key{}, err
		}

		switch r {
		case 'q', 'Q':
			return cio.NewKey(nil, chkm.Key_ExitApp), nil
		case 'p', 'P':
			return cio.NewKey(nil, chkm.Key_SelectPool), nil
		case 'd', 'D':
			return cio.NewKey(nil, chkm.Key_CheckDomainCertificates), nil
		case 'l', 'L':
			return cio.NewKey(nil, chkm.Key_ListLoadedPools), nil
		default:
			return cio.NewKey(nil, chkm.Key_Nothing), nil
		}
	}
}
func GetFileFromUrl(url string) (data []byte, err error) {
	var httpResp *http.Response
	httpResp, err = http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() {
		derr := httpResp.Body.Close()
		if derr != nil {
			err = errors.Combine(err, derr)
		}
	}()

	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.ErrorFromFormattedText(Errf_HttpRequestFailedWithStatus, httpResp.StatusCode)
	}

	data, err = io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}
