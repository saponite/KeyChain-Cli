package cmd

import (
	"KeyChain-CLI/config"
	"context"

	"github.com/spf13/cobra"
)

func RootCmd(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "KeyChain-CLI",
		Short: "Создание пары ключей, подписание файлы и проверка подписи.",
		Long:  `Набор инструментов для генерации пар ключей в PEM-файлах, подписи файлов и проверки подписей.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd, app)
		},
	}

	return root
}

func initializeConfig(cmd *cobra.Command, app *App) error {
	localViper, err := config.LoadYamlConfig(app.Logger)
	if err != nil {
		return err
	}

	// привязка флагов
	if err = config.BindFlags(cmd, localViper, app.Logger); err != nil {
		return err
	}

	ctx := context.WithValue(cmd.Context(), config.ViperKey, localViper)
	cmd.SetContext(ctx)

	return nil
}
