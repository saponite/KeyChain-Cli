package signatures

import (
	"KeyChain-CLI/cmd"

	"github.com/spf13/cobra"
)

func Init(rootCmd *cobra.Command, app *cmd.App) {
	var signaturesCmd = &cobra.Command{
		Use:   "signatures",
		Short: "Создание и проверка подписей.",
		Long:  `Используйте подкоманды для создания подписи (.sig) с закрытым ключом и проверки подписи с помощью открытого ключа.`,
	}

	signaturesCmd.AddCommand(newSignCmd(app))
	rootCmd.AddCommand(signaturesCmd)
}
