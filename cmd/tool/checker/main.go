package main

import (
	"os"

	"github.com/vault-thirteen/auxie/cio"
	"github.com/vault-thirteen/auxie/errors"

	ver "github.com/vault-thirteen/auxie/Versioneer/classes/Versioneer"

	h "github.com/vault-thirteen/SSL-Checker/pkg/helper"
	chm "github.com/vault-thirteen/SSL-Checker/pkg/models/tool/checker"
)

func main() {
	showIntro()

	cla, err := chm.NewCLA()
	mustBeNoError(err)

	var appSettings *chm.AppSettings
	appSettings, err = chm.NewAppSettings(cla.SettingsFilePath)
	mustBeNoError(err)

	var app *chm.App
	app, err = chm.NewApp(appSettings)
	mustBeNoError(err)

	err = app.Run()
	mustBeNoError(err)
}
func mustBeNoError(err error) {
	if err != nil {
		errors.LogError(err)
		os.Exit(h.ExitCode_GenericError)
	}
}
func showIntro() {
	versioneer, err := ver.New(false)
	mustBeNoError(err)
	versioneer.ShowIntroText(chm.AppName)
	versioneer.ShowComponentsInfoText()
	cio.PrintMessage()
}
