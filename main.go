package main

import (
	"KeyChain-CLI/cmd"
	"KeyChain-CLI/cmd/keys"
	"KeyChain-CLI/cmd/signatures"
	"KeyChain-CLI/logger"
)

func main() {
	logFile, err := logger.New("app.log")
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = logFile.Close(); err != nil {
			logFile.Error("ошибка закрытия файла: ", err)
		}
	}()

	app := &cmd.App{Logger: logFile}

	rootCmd := cmd.RootCmd(app)
	keys.Init(rootCmd, app)
	signatures.Init(rootCmd)

	if err = rootCmd.Execute(); err != nil {
		logFile.Error("ошибка выполнения команды: ", err)
	}
}
