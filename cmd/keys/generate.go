package keys

import (
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
)

type PrivateKeyGen struct {
	outputPath string
	keyBitSize int
	saltSize   int
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Генерация пар ключей.",
	Long:  `Сгенерируйте пару ключей RSA и сохраните их в PEM-файлах. Закрытый ключ будет зашифрован с помощью парольной фразы, которую вам нужно будет ввести. Используется шифрование AES с функцией получения ключа Argon2.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pkOut, _ := cmd.Flags().GetString("priv-out")
		pkSize, _ := cmd.Flags().GetInt("priv-size")
		saltSize, _ := cmd.Flags().GetInt("salt-size")

		pkGenConfig := PrivateKeyGen{
			outputPath: pkOut,
			keyBitSize: pkSize,
			saltSize:   saltSize,
		}

		privateKey, err := generatePrivateKey(pkGenConfig)
		if err != nil {
			return fmt.Errorf("ошибка генерации закрытого ключа: %w", err)
		}

		pubOut, _ := cmd.Flags().GetString("pub-out")
		err = generatePublicKey(pubOut, privateKey)
		if err := generatePublicKey(pubOut, privateKey); err != nil {
			return fmt.Errorf("ошибка генерации открытого ключа: %w", err)
		}

		return nil
	},
}

func init() {
	keysCmd.AddCommand(keysGenerateCmd)
	keysGenerateCmd.Flags().String("pub-out", "pub_key.pem", "Путь для сохранения открытого ключа.")
	keysGenerateCmd.Flags().String("priv-out", "priv_key.pem", "Путь для сохранения закрытого ключа.")
	keysGenerateCmd.Flags().Int("priv-size", 2048, "Размер закрытого ключа в битах.")
	keysGenerateCmd.Flags().Int("salt-size", 16, "Размер соли, используемый при выводе ключа, в байтах.")
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
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	salt, err := makeSalt(cfg.saltSize)
	if err != nil {
		return nil, err
	}

	key, err := cryptoUtils.DeriveKey(cryptoUtils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
	})
	if err != nil {
		return nil, err
	}

	crypter, err := cryptoUtils.MakeCrypter(key)
	if err != nil {
		return nil, err
	}

	nonce, err := cryptoUtils.MakeNonce(crypter)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return privateKey, nil
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
