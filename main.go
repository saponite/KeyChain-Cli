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

	rootCmd := cmd.RootCmd()
	keys.Init(rootCmd)
	signatures.Init(rootCmd)
	if err = rootCmd.Execute(); err != nil {
		logFile.Error("ошибка обработки аргументов", err)
	}
}
