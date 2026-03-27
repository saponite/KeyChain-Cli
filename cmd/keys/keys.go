package keys

import (
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Управление парами ключей.",
	Long:  `Используйте подкоманды для создания пар открытых и закрытых ключей в файлах PEM.`,
}

func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(keysCmd)
}
