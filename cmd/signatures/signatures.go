package signatures

import (
	"github.com/spf13/cobra"
)

var signaturesCmd = &cobra.Command{
	Use:   "signatures",
	Short: "Создание и проверка подписей.",
	Long:  `Используйте подкоманды для создания подписи (.sig) с закрытым ключом и проверки подписи с помощью открытого ключа.`,
}

func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(signaturesCmd)
}
