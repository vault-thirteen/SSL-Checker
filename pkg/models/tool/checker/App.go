package chm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"

	"github.com/vault-thirteen/auxie/cio"
	"github.com/vault-thirteen/auxie/errors"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
	l "github.com/vault-thirteen/SSL-Checker/pkg/models/CRL"
	cm "github.com/vault-thirteen/SSL-Checker/pkg/models/common"
	chkm "github.com/vault-thirteen/SSL-Checker/pkg/models/tool/checker/keyboard"
)

const AppName = "Tool"

type App struct {
	settings *AppSettings
	colour   cm.Colour

	customRootCertificatePools []cm.RootCertificatePool
	systemCACerts              []*x509.Certificate
	systemCRLs                 *l.CRLs
	customCRLs                 []*l.CRLs

	// poolIdx is an index of a pool used for certificate verifications and CRL
	// procession. It switches between different sets of root CA certificates
	// and CRLs. When set to null, checker uses system pool of root certificates
	// and associated pool of CRLs. When this index is set to non-null value,
	// then a custom pool of root certificates is used together with an
	// associated custom pool of CRLs. Such complexity is required for strict
	// and fair procession of certificates and their revocation lists.
	poolIdx *int
}

func NewApp(settings *AppSettings) (app *App, err error) {
	if settings == nil {
		return nil, errors.ErrorFromText(cm.Err_NullPointer)
	}

	app = &App{
		settings: settings,
	}

	if app.settings.DebugMode {
		cio.PrintMessage(cm.Msg_DebugModeIsEnabled)
	}

	if app.settings.EnableAnsiColours {
		err = cio.EnableAnsiSymbolsInTerminal()
		if err != nil {
			return nil, err
		}
	}

	err = app.Init()
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (app *App) Init() (err error) {
	// Colours.
	{
		cRed := h.AnsiSetColorRed
		cYellow := h.AnsiSetColorYellow
		cGreen := h.AnsiSetColorGreen

		app.colour = cm.Colour{
			None:   nil,
			Red:    &cRed,
			Yellow: &cYellow,
			Green:  &cGreen,
		}
	}

	// Root certificates.
	{
		// Custom root certificate pools.
		err = app.initCustomRootCertificatePools()
		if err != nil {
			return err
		}

		// System root CA certificates.
		app.systemCACerts, err = h.GetSystemRootCertificates()
		if err != nil {
			return err
		}
	}

	// CRLs.
	{
		app.systemCRLs, err = l.NewCRLs(app.settings.DebugMode, app.settings.CrlTtlMinutes)
		if err != nil {
			return err
		}

		var x *l.CRLs
		app.customCRLs = make([]*l.CRLs, 0, len(app.settings.PoolFilesSettings))
		for i := 0; i < len(app.customRootCertificatePools); i++ {
			x, err = l.NewCRLs(app.settings.DebugMode, app.settings.CrlTtlMinutes)
			if err != nil {
				return err
			}

			app.customCRLs = append(app.customCRLs, x)
		}
	}

	return nil
}
func (app *App) initCustomRootCertificatePools() (err error) {
	app.customRootCertificatePools = make([]cm.RootCertificatePool, 0, len(app.settings.PoolFilesSettings))

	var rcp *cm.RootCertificatePool
	n := len(app.settings.PoolFilesSettings)
	for i, pfs := range app.settings.PoolFilesSettings {
		cio.Print(cio.FormatMessage(cm.Msgf_NN, i+1, n))

		rcp, err = cm.NewRootCertificatePool(pfs.PoolName, pfs.FilePath, app.settings.UseColours, app.settings.CertFileVerificationDelayMs)
		if err != nil {
			return err
		}
		if rcp == nil {
			return errors.ErrorFromText(cm.Err_NullPointer)
		}

		app.customRootCertificatePools = append(app.customRootCertificatePools, *rcp)
	}

	cio.PrintMessage(cio.FormatMessage(cm.Msgf_RootCertificatePoolsLoaded, n))

	return nil
}
func (app *App) Run() (err error) {
	var shouldContinue = true
	var key cio.Key
	for shouldContinue {
		if !app.settings.DebugMode {
			cio.PrintMessage(cm.Msg_WorkHint)
		} else {
			cio.PrintMessage(cm.Msg_WorkHint_DBG)
		}

		key, err = h.GetInputKey(app.settings.DebugMode)
		if err != nil {
			return err
		}

		switch key.Code() {
		case chkm.Key_ExitApp:
			{
				shouldContinue = false
				continue
			}

		case chkm.Key_SelectPool:
			{
				cio.Print(cm.Msg_EnterCertificatePoolIndex)

				app.poolIdx, err = app.getPoolIndex()
				if err != nil {
					errors.LogError(err)
					continue
				}

				if app.poolIdx == nil {
					app.printText(cm.Msg_UsingSystemCertificatePool, app.colour.Green)
				} else {
					msg := cio.FormatMessage(cm.Msgf_UsingCustomCertificatePool, app.customRootCertificatePools[*app.poolIdx].Name())
					app.printText(msg, app.colour.Yellow)
				}
			}

		case chkm.Key_CheckDomainCertificates:
			{
				cio.Print(cm.Msg_EnterDomainName)
				var domain string
				domain, err = cio.GetInputString(true)
				if err != nil {
					errors.LogError(err)
					continue
				}
				if len(domain) == 0 {
					continue
				}

				cio.Print(cm.Msg_EnterPortNumber)
				var portStr string
				portStr, err = cio.GetInputString(true)
				if err != nil {
					errors.LogError(err)
					continue
				}

				var port int
				if len(portStr) == 0 {
					port = h.DefaultPort
				} else {
					port, err = strconv.Atoi(portStr)
					if err != nil {
						errors.LogError(err)
						continue
					}
				}

				err = h.ValidateDomainAndPort(&domain, port)
				if err != nil {
					errors.LogError(err)
					continue
				}

				err = app.checkDomainCertificates(domain, uint16(port))
				if err != nil {
					errors.LogError(err)
					app.printText(cm.Msg_DomainCertificatesCheckHasFailed, app.colour.Red)
					continue
				}
			}

		case chkm.Key_ListLoadedPools:
			{
				var sb strings.Builder
				sb.WriteString(cm.Msg_PoolListHeader + h.CRLF)

				for i, rcp := range app.customRootCertificatePools {
					sb.WriteString(cio.FormatMessage(cm.Msgf_PoolListItem, i, rcp.Name()))
				}

				cio.PrintMessage(sb.String())
			}

		case chkm.Key_Nothing:
			continue

		default:
			continue
		}
	}

	return nil
}

// getPoolIndex reads a pool index (integer number) from console (command
// prompt, terminal emulator) and verifies its value. Negative index values
// mean that checker will switch to system pool of root CA certificates and
// associated CRLs. Positive index switches to a custom pool of root CA
// certificates and associated CRLs.
func (app *App) getPoolIndex() (poolIndex *int, err error) {
	var idx int
	idx, err = cio.GetInputInt()
	if err != nil {
		return nil, err
	}

	if idx < 0 {
		return nil, nil
	}

	customPoolsCount := len(app.customRootCertificatePools)
	if customPoolsCount <= 0 {
		return nil, errors.ErrorFromFormattedText(cm.Errf_PoolIsNotFound, idx)
	}

	if idx > customPoolsCount-1 {
		return nil, errors.ErrorFromFormattedText(cm.Errf_PoolIsNotFound, idx)

	}

	return &idx, nil
}
func (app *App) checkDomainCertificates(domain string, portNumber uint16) (err error) {
	address := h.FormatHostPort(domain, portNumber)
	cio.PrintMessage(cio.FormatMessage(cm.Msgf_ProcessingAddress, address))

	// Get and show certificates.
	var allCerts []*x509.Certificate
	{
		allCerts, err = app.getDomainCertificates(address)
		if err != nil {
			return err
		}
		cio.PrintMessage(cio.FormatMessage(cm.Msgf_RetrievedCertificatesCount, len(allCerts)))

		var details []*cm.CertificateDetails
		details, err = app.getCertificateDetails(allCerts)
		if err != nil {
			return err
		}

		app.printCertificateDetails(details)
	}

	// Verification.
	{
		var certErrors []error
		err, certErrors = app.verifyCertificates(allCerts, domain)
		if err != nil {
			return err
		}

		certErrorsNum := 0
		for i, certError := range certErrors {
			if certError != nil {
				certErrorsNum++
				var certErrMsg = allCerts[i].Subject.CommonName + " : " + certError.Error()
				app.printText(certErrMsg, app.colour.Red)
			}
		}

		if certErrorsNum == 0 {
			report := cm.Msg_NoErrorsWereFoundInCertificates
			app.printText(report, app.colour.Green)
		}
	}

	// Check certificate revocation lists.
	{
		var certErrors []error
		err, certErrors = app.checkRevocations(allCerts)
		if err != nil {
			return err
		}

		certErrorsNum := 0
		for i, certError := range certErrors {
			if certError != nil {
				certErrorsNum++
				var certErrMsg = allCerts[i].Subject.CommonName + " : " + certError.Error()
				app.printText(certErrMsg, app.colour.Red)
			}
		}

		if certErrorsNum == 0 {
			app.printText(cm.Msg_NoRevocatedCertificates, app.colour.Green)
		}
	}

	return nil
}
func (app *App) getCertificateDetails(certs []*x509.Certificate) (details []*cm.CertificateDetails, err error) {
	var d *cm.CertificateDetails
	for _, c := range certs {
		d, err = cm.NewCertificateDetails(c)
		if err != nil {
			return nil, err
		}

		details = append(details, d)
	}

	return details, nil
}
func (app *App) printCertificateDetails(details []*cm.CertificateDetails) {
	cio.PrintMessage(cm.Msg_Separator)
	for _, d := range details {
		d.Print()
		cio.PrintMessage(cm.Msg_Separator)
	}
}
func (app *App) verifyCertificates(allCerts []*x509.Certificate, domain string) (err error, certErrors []error) {
	if len(allCerts) < 1 {
		return errors.ErrorFromText(cm.Err_NoCertificates), nil
	}

	var useSystemRootCertificates bool = (app.poolIdx == nil)
	if useSystemRootCertificates {
		app.printText(cm.Msg_UsingSystemRootCertificates, app.colour.Green)
	} else {
		msg := cio.FormatMessage(cm.Msgf_UsingCustomRootCertificatesPool, app.customRootCertificatePools[*app.poolIdx].Name())
		app.printText(msg, app.colour.Yellow)
	}

	var intermediateCerts *x509.CertPool = x509.NewCertPool()
	for i := 1; i < len(allCerts); i++ {
		intermediateCerts.AddCert(allCerts[i])
	}
	certErrors = make([]error, len(allCerts))

	opts := x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediateCerts,
	}

	// Switch pools.
	if useSystemRootCertificates {
		opts.Roots = nil
	} else {
		opts.Roots = app.customRootCertificatePools[*app.poolIdx].Pool()
	}

	// 1. Verify the leaf certificate.
	var vErr error
	_, vErr = allCerts[0].Verify(opts)
	certErrors[0] = vErr

	// 2. Verify other certificates.
	opts.DNSName = ""
	for i := 1; i < len(allCerts); i++ {
		_, vErr = allCerts[i].Verify(opts)
		certErrors[i] = vErr
	}

	return nil, certErrors
}
func (app *App) checkRevocations(allCerts []*x509.Certificate) (err error, certErrors []error) {
	cio.PrintMessage(cm.Msg_CheckingRevocationLists)
	certErrors = make([]error, len(allCerts))
	var useSystemRootCertificates bool = (app.poolIdx == nil)

	// Switch pools.
	var caCerts []*x509.Certificate
	var crlsPool *l.CRLs
	if useSystemRootCertificates {
		caCerts = app.systemCACerts
		crlsPool = app.systemCRLs
	} else {
		caCerts = app.customRootCertificatePools[*app.poolIdx].Certificates()
		crlsPool = app.customCRLs[*app.poolIdx]
	}

	// 1. Fetch all possible CRLs and verify them. Even if we will not look
	// into all the lists, we must fetch and verify all of them as a safety
	// measure, ensuring that all CRLs are reachable and healthy. Healthy CRLs
	// are cached into memory so that their next retrieval does not need access
	// to the Internet network. Even if the CRLs are already in cache, here we
	// check their "freshness" and re-download them in case they become
	// out-of-date.
	var crl *l.CRL
	for _, cert := range allCerts {
		for _, crlUrl := range cert.CRLDistributionPoints {
			crl, err = crlsPool.GetActiveCRL(crlUrl, caCerts)
			if err != nil {
				return err, nil
			}
		}
	}

	// 2. Check revocation status against the cached CRLs. The first found
	// revocation status is enough to be sure that a certificated was revoked.
	var isRevoked bool
	var revocationDetails *x509.RevocationListEntry
	for i, cert := range allCerts {
		for _, crlUrl := range cert.CRLDistributionPoints {
			crl, err = crlsPool.GetActiveCRL(crlUrl, caCerts)
			if err != nil {
				return err, nil
			}

			isRevoked, revocationDetails = h.IsCertificateRevocated(cert, crl.RevocationList())
			if isRevoked {
				certErrors[i] = cm.Error_RevocatedCertificate(revocationDetails)
				break // Switch to the next certificate.
			}
		}
	}

	return nil, nil
}

// getDomainCertificates connects to the address and reads SSL certificates
// from the server. Address must be in the form of 'host:port', e.g.
// 'example.org:443'.
func (app *App) getDomainCertificates(address string) (certs []*x509.Certificate, err error) {
	var host, port string
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	xAddress := net.JoinHostPort(host, port)
	if xAddress != address {
		return nil, errors.ErrorFromText(cm.Err_BadAddress)
	}

	address = xAddress
	serverName := host

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,

		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
			if len(rawCerts) == 0 {
				return errors.ErrorFromText(cm.Err_NoCertificates)
			}

			// 1. Server's certificate.
			var leaf *x509.Certificate
			leaf, err = x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return errors.ErrorWithPrefix(err, cm.Err_CertificateParseError)
			}
			certs = append(certs, leaf)

			// 2. Intermediate certificates.
			var iCert *x509.Certificate
			for i := 1; i < len(rawCerts); i++ {
				iCert, err = x509.ParseCertificate(rawCerts[i])
				if err != nil {
					return errors.ErrorWithPrefix(err, cm.Err_CertificateParseError)
				}

				certs = append(certs, iCert)
			}

			return nil
		},
	}

	var conn *tls.Conn
	conn, err = tls.Dial(h.NetworkType, address, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		derr := conn.Close()
		if derr != nil {
			err = errors.Combine(err, derr)
		}
	}()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.ErrorFromText(cm.Err_NoCertificates)
	}

	if len(state.PeerCertificates) != len(certs) {
		return nil, errors.ErrorFromText(cm.Err_CertificateCountMismatch)
	}

	if len(certs) == 0 {
		return nil, errors.ErrorFromText(cm.Err_NoCertificates)
	}

	return certs, nil
}
func (app *App) printText(msg string, colour *string) {
	if !app.settings.UseColours {
		cio.PrintMessage(msg)
		return
	}

	if colour == nil {
		errors.LogError(errors.ErrorFromText(cm.Err_ColourIsNotSet))
		cio.PrintMessage(msg)
		return
	}

	colouredMsg := *colour + msg + h.AnsiSetColorDefault
	cio.PrintMessage(colouredMsg)
}
