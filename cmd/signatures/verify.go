package signatures

import (
	"KeyChain-CLI/cmd"
	"KeyChain-CLI/config"
	internalsignatures "KeyChain-CLI/internal/signatures"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newVerifyCmd(app *cmd.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "verify",
		Short: "Проверить подпись файла.",
		Long:  `Проверяет цифровую подпись файла с помощью RSA публичного ключа. Ожидается файл подписи с именем "<имя_файла>.sig" в той же директории что и проверяемый файл. Публичный ключ должен быть в формате PEM.`,
		RunE: func(c *cobra.Command, args []string) error {
			v := c.Context().Value(config.ViperKey).(*viper.Viper)

			pubKeyPath := v.GetString("public-key-path")
			filePath := v.GetString("file-path")

			app.Logger.Print("Проверка подписи файла...")
			app.Logger.Info("проверка подписи файла: ", filePath)

			signerInfo, err := internalsignatures.VerifyFile(pubKeyPath, filePath)
			if err != nil {
				app.Logger.Error("ошибка верификации: ", err)
				app.Logger.Print("Ошибка: подпись недействительна")
				return err
			}

			app.Logger.Print("Подпись действительна.")
			app.Logger.Print("Файл: ", filepath.Base(filePath))
			app.Logger.Print("Подписан: ", string(signerInfo))
			app.Logger.Info("верификация успешна, файл: ", filePath)

			return nil
		},
	}

	c.Flags().String("public-key-path", "pub_key.pem", "Путь к публичному ключу.")
	c.Flags().String("file-path", "", "Путь к файлу для проверки подписи.")

	if err := c.MarkFlagRequired("file-path"); err != nil {
		panic(fmt.Sprintf("флаг 'file-path' не зарегистрирован: %v", err))
	}

	return c
}
