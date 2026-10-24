package chm

import (
	"errors"
	"os"

	cm "github.com/vault-thirteen/SSL-Checker/pkg/models/common"
)

// CLA means Command Line Arguments.
type CLA struct {
	SettingsFilePath string
}

func NewCLA() (cla *CLA, err error) {
	if len(os.Args) < 2 {
		return nil, errors.New(cm.Err_SettingsFileIsNotSpecified)
	}

	cla = &CLA{
		SettingsFilePath: os.Args[1],
	}

	return cla, nil
}
