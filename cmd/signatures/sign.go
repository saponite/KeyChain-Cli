package signatures

import (
	"KeyChain-CLI/cmd"
	"KeyChain-CLI/config"
	internalsignatures "KeyChain-CLI/internal/signatures"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newSignCmd(app *cmd.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "sign",
		Short: "Подписать файл.",
		Long:  `Подписывает файл с помощью закрытого ключа и сохраняет подпись в .sig файл.`,
		PreRunE: func(c *cobra.Command, args []string) error {
			signerID := c.Flag("signer-id").Value.String()
			if err := internalsignatures.ValidateSignerID(signerID); err != nil {
				app.Logger.Error("невалидный signer-id: ", err)
				app.Logger.Print("Ошибка: ", err)
				return err
			}

			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			v := c.Context().Value(config.ViperKey).(*viper.Viper)

			privateKeyPath := v.GetString("private-key-path")
			filePath := v.GetString("file-path")
			signerID := v.GetString("signer-id")

			app.Logger.Print("Подписание файла...")
			app.Logger.Info("подписание файла: ", filePath)

			if err := internalsignatures.SignFile(privateKeyPath, filePath, signerID); err != nil {
				app.Logger.Error("ошибка подписания файла: ", err)
				app.Logger.Print("Ошибка: не удалось подписать файл")
				return err
			}

			app.Logger.Print("Файл успешно подписан: ", filePath+".sig")
			app.Logger.Info("файл подписан: ", filePath)

			return nil
		},
	}

	c.Flags().String("private-key-path", "priv_key.pem", "Путь к закрытому ключу.")
	c.Flags().String("file-path", "", "Путь к файлу для подписи.")
	c.Flags().String("signer-id", "", "Имя или идентификатор подписанта.")
	if err := c.MarkFlagRequired("signer-id"); err != nil {
		panic(fmt.Sprintf("флаг 'signer-id' не зарегистрирован: %ц", err))
	}
	if err := c.MarkFlagRequired("file-path"); err != nil {
		panic(fmt.Sprintf("флаг 'file-path' не зарегистрирован: %v", err))
	}

	return c
}
