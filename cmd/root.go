package cmd

import (
	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "braveSigner",
		Short: "Создание пары ключей, подписание файлы и проверка подписи.",
		Long:  `Набор инструментов для генерации пар ключей в PEM-файлах, подписи файлов и проверки подписей.`,
	}
}
