package cmd

import (
	"KeyChain-CLI/config"
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var version string = "dev"

func RootCmd(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "KeyChain-CLI",
		Short: "Создание пары ключей, подписание файлы и проверка подписи.",
		Long:  `Набор инструментов для генерации пар ключей в PEM-файлах, подписи файлов и проверки подписей.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd, app)
		},
	}

	root.AddCommand(&cobra.Command{
		Use:    "gendocs",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := generateDocs(root, "./docs"); err != nil {
				app.Logger.Error("ошибка генерации документации: ", err)

				return err
			}
			app.Logger.Print("Документация сгенерирована в ./docs")

			return nil
		},
	})

	return root
}

func generateDocs(rootCmd *cobra.Command, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return doc.GenMarkdownTree(rootCmd, dir)
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
