package keys

import (
	"KeyChain-CLI/cmd"
	"KeyChain-CLI/config"
	"KeyChain-CLI/cryptoUtils"
	"KeyChain-CLI/utils"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type PrivateKeyGen struct {
	time, memory, keyLen uint32
	threads              uint8
	outputPath           string
	keyBitSize           int
	saltSize             int
}

func generatePublicKey(path string, privateKey *rsa.PrivateKey) (err error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("не удалось получить абсолютный путь: %w", err)
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("ошибка маршализации открытого ключа: %w", err)
	}

	file, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("не удалось создать файл открытого ключа: %w", err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("ошибка закрытия файла: %w", closeErr)
		}
	}()

	if err = pem.Encode(file, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}); err != nil {
		return fmt.Errorf("ошибка кодирования PEM-блока открытого ключа: %w", err)
	}

	return nil
}

func generatePrivateKey(cfg PrivateKeyGen) (*rsa.PrivateKey, error) {
	absPath, err := filepath.Abs(cfg.outputPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить абсолютный путь: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, cfg.keyBitSize)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации закрытого ключа: %w", err)
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return nil, fmt.Errorf("ошибка ввода секретной фразы: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	salt, err := makeSalt(cfg.saltSize)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания соли: %w", err)
	}

	key, err := cryptoUtils.DeriveKey(cryptoUtils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       cfg.time,
		Memory:     cfg.memory,
		Threads:    cfg.threads,
		KeyLen:     cfg.keyLen,
	})
	if err != nil {
		return nil, fmt.Errorf("ошибка создания ключа: %w", err)
	}

	crypter, err := cryptoUtils.MakeCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	nonce, err := cryptoUtils.MakeNonce(crypter)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	encryptedData := crypter.Seal(nil, nonce, privateKeyBytes, nil)

	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedData,
		Headers: map[string]string{
			"Nonce": base64.StdEncoding.EncodeToString(nonce),
			"Salt":  base64.StdEncoding.EncodeToString(salt),
			"KDF":   "Argon2",
		},
	}

	if err = savePrivateKeyToPEM(absPath, block); err != nil {
		return nil, fmt.Errorf("ошибка сохранения приватного ключа в файл .pem: %w", err)
	}

	return privateKey, nil
}

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

			pkGenConfig := PrivateKeyGen{
				time:       tm,
				memory:     mem,
				threads:    ths,
				keyLen:     kl,
				outputPath: pkOut,
				keyBitSize: pkSize,
				saltSize:   saltSize,
			}

			app.Logger.Print("Происходит генерация закрытого ключа...")
			app.Logger.Info("генерация закрытого ключа запущена, генерация происходит в файл по пути: ", pkOut)
			privateKey, err := generatePrivateKey(pkGenConfig)
			if err != nil {
				app.Logger.Error("ошибка генерации закрытого ключа: ", err)
				app.Logger.Print("Ошибка: не удалось сгенерировать ключ")

				return err
			}

			pubOut := localViper.GetString("public-key-path")
			app.Logger.Print("Происходит генерация открытого ключа...")
			if err = generatePublicKey(pubOut, privateKey); err != nil {
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

func savePrivateKeyToPEM(path string, block *pem.Block) (err error) {
	f, err := os.Create(path)
	if err != nil {
		err = fmt.Errorf("не удалось создать файл закрытого ключа: %w", err)
	}

	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = fmt.Errorf("ошибка закрытия файла закрытого ключа: %w", closeErr)
		}
	}()

	if err = pem.Encode(f, block); err != nil {
		err = fmt.Errorf("ошибка кодирования закрытого ключа: %w", err)
	}

	return nil
}

func makeSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ошибка генерации соли: %w", err)
	}

	return salt, nil
}
