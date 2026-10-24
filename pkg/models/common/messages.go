package cm

import (
	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
)

const (
	Msg_OK                               = "OK"
	Msg_DebugModeIsEnabled               = "Debug mode is enabled."
	Msg_EnterCertificatePoolIndex        = "Enter certificate pool index (0 .. N) or -1 to use system certificate pool: "
	Msg_UsingSystemCertificatePool       = "Using system certificate pool."
	Msg_EnterDomainName                  = "Enter domain name: "
	Msg_EnterPortNumber                  = "Enter port number (443 if empty): "
	Msg_Separator                        = "---------------------------------------------------------------------------"
	Msg_UsingSystemRootCertificates      = "Using system root certificates."
	Msg_NoErrorsWereFoundInCertificates  = "No errors were found in certificates."
	Msg_CheckingRevocationLists          = "Checking revocation lists ..."
	Msg_NoRevocatedCertificates          = "No revocated certificates."
	Msg_PoolListHeader                   = "List of loaded root certificate pools"
	Msg_DomainCertificatesCheckHasFailed = "Domain certificates check has failed!"

	Msg_WorkHint = "[ESC] = Quit, " +
		"[P] = Pool selection, " +
		"[D] = Check domain certificates, " +
		"[L] = List certificate pools."

	Msg_WorkHint_DBG = "[Q] = Quit, " +
		"[P] = Pool selection, " +
		"[D] = Check domain certificates, " +
		"[L] = List certificate pools."

	Msgf_LoadingRootCertificatePool      = "Loading root certificate pool '%s' ..."
	Msgf_NN                              = "[%d / %d] "
	Msgf_RootCertificatePoolsLoaded      = "%d root certificate pools were loaded."
	Msgf_UsingCustomCertificatePool      = "Using custom certificate pool: %s."
	Msgf_ProcessingAddress               = "Processing address: %s"
	Msgf_RetrievedCertificatesCount      = "Number of retrieved certificates: %d"
	Msgf_UsingCustomRootCertificatesPool = "Using custom root certificates pool: %s"
	Msgf_PoolListItem                    = "\t[%02d] %s" + h.CRLF
	Msgf_DownloadingCrl                  = "Downloading CRL, URL: %s"
)
