package keys

import (
	"KeyChain-CLI/cmd"

	"github.com/spf13/cobra"
)

func Init(rootCmd *cobra.Command, app *cmd.App) {
	var keysCmd = &cobra.Command{
		Use:   "keys",
		Short: "Управление парами ключей.",
		Long:  `Используйте подкоманды для создания пар открытых и закрытых ключей в файлах PEM.`,
	}

	keysCmd.AddCommand(newKeysGenerateCmd(app))
	rootCmd.AddCommand(keysCmd)
}
