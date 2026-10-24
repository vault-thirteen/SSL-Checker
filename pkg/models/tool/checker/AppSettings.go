package chm

import (
	"bytes"
	"encoding/json"

	"github.com/vault-thirteen/auxie/file"

	cm "github.com/vault-thirteen/SSL-Checker/pkg/models/common"
)

type AppSettings struct {
	// A flag to switch on debug mode. Debug mode uses more primitive functions
	// to work with terminal emulator (console, command prompt) than in normal
	// mode. This mode may be required due to limitations of various IDEs and
	// environments which do not fully support terminal emulation. Also, this
	// mode enables verbose messages about downloading of CRL files.
	DebugMode bool `json:"debugMode"`

	// A flag enabling ANSI colouring information for those prints which use
	// colours. Colours are used in important messages and some reports.
	UseColours bool `json:"useColours"`

	// A flag which forces a switch in the console mode to enable ANSI colours.
	// This flag is used for old terminal emulators in Windows O.S., such as
	// 'cmd.exe', which do not enable ANSI colours by default.
	EnableAnsiColours bool `json:"enableAnsiColours"`

	// List of custom pools of root CA certificates which can be used for
	// certificate checks. These custom pools only set root CA certificates. All
	// the certificate revocation lists (CRLs) are downloaded and cached
	// automatically during the runtime.
	PoolFilesSettings []cm.PoolFileSettings `json:"poolFiles"`

	// Time in minutes for which a CRL is considered fresh. CRLs older than
	// this time are considered out-of-date and can not be used.
	CrlTtlMinutes uint `json:"crlTtlMinutes"`

	// CertFileVerificationDelayMs is a delay after verification of each
	// certificate file, used only at the program start-up. It is not used
	// during normal checks. This delay is used to increase level of politeness
	// of the program's behaviour during certificate data retrievals at the
	// start-up. Please, do note that some servers have very strict rules about
	// how often and how intensively you may connect to them. If the program
	// fails to get certificate files, try increasing the delay or wait some
	// time for the servers to cool down.
	CertFileVerificationDelayMs uint `json:"certFileVerificationDelayMs"`
}

func NewAppSettings(filePath string) (appSettings *AppSettings, err error) {
	var buf []byte
	buf, err = file.GetFileContents(filePath)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(buf))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()

	err = decoder.Decode(&appSettings)
	if err != nil {
		return nil, err
	}

	return appSettings, nil
}
