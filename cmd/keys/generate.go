package keys

import (
	"KeyChain-CLI/cmd"
	"KeyChain-CLI/config"
	"KeyChain-CLI/internal/keys"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newKeysGenerateCmd(app *cmd.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "generate",
		Short: "Генерация пар ключей.",
		Long:  `Сгенерируйте пару ключей RSA и сохраните их в PEM-файлах. Закрытый ключ будет зашифрован с помощью парольной фразы, которую вам нужно будет ввести. Используется шифрование AES с функцией получения ключа Argon2.`,
		RunE: func(c *cobra.Command, args []string) error {
			localViper := c.Context().Value(config.ViperKey).(*viper.Viper)
			tm := localViper.GetUint32("time")
			mem := localViper.GetUint32("memory")
			ths := localViper.GetUint8("threads")
			kl := localViper.GetUint32("keyLen")
			pkOut := localViper.GetString("private-key-path")
			pkSize := localViper.GetInt("private-key-size")
			saltSize := localViper.GetInt("salt-size")

			pkGenConfig := keys.GenerateConfig{
				Time:       tm,
				Memory:     mem,
				Threads:    ths,
				KeyLen:     kl,
				OutputPath: pkOut,
				KeyBitSize: pkSize,
				SaltSize:   saltSize,
			}

			app.Logger.Print("Происходит генерация закрытого ключа...")
			app.Logger.Info("генерация закрытого ключа запущена, генерация происходит в файл по пути: ", pkOut)
			privateKey, err := keys.GeneratePrivateKey(pkGenConfig)
			if err != nil {
				app.Logger.Error("ошибка генерации закрытого ключа: ", err)
				app.Logger.Print("Ошибка: не удалось сгенерировать ключ")

				return err
			}

			pubOut := localViper.GetString("public-key-path")
			app.Logger.Print("Происходит генерация открытого ключа...")
			if err = keys.GeneratePublicKey(pubOut, privateKey); err != nil {
				app.Logger.Error("ошибка генерации открытого ключа: ", err)

				return err
			}

			app.Logger.Print("Генерация завершена. Ключи успешно сохранены:")
			app.Logger.Print("  Закрытый ключ: ", pkOut)
			app.Logger.Print("  Открытый ключ: ", pubOut)
			app.Logger.Info("ключи успешно сгенерированы")

			return nil
		},
	}

	c.Flags().Uint32("time", 1, "Время генерации ключа.")
	c.Flags().Uint32("memory", 2<<15, "Количество памяти для генерации ключа (в мегабайтах).")
	c.Flags().Uint8("threads", 4, "Количество потоков, которые нужно задействовать для генерации ключа.")
	c.Flags().Uint32("keyLen", 32, "Длина ключа (в байтах).")
	c.Flags().String("public-key-path", "pub_key.pem", "Путь для сохранения открытого ключа.")
	c.Flags().String("private-key-path", "priv_key.pem", "Путь для сохранения закрытого ключа.")
	c.Flags().Int("private-key-size", 2048, "Размер закрытого ключа в битах.")
	c.Flags().Int("salt-size", 16, "Размер соли, используемый при выводе ключа, в байтах.")

	return c
}
