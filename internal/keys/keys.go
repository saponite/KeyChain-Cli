package keys

import (
	"KeyChain-CLI/internal/crypto"
	utils "KeyChain-CLI/terminal"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type GenerateConfig struct {
	Time, Memory, KeyLen uint32
	Threads              uint8
	OutputPath           string
	KeyBitSize           int
	SaltSize             int
}

func GeneratePublicKey(path string, privateKey *rsa.PrivateKey) (err error) {
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

func GeneratePrivateKey(cfg GenerateConfig) (*rsa.PrivateKey, error) {
	absPath, err := filepath.Abs(cfg.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить абсолютный путь: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, cfg.KeyBitSize)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации закрытого ключа: %w", err)
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return nil, fmt.Errorf("ошибка ввода секретной фразы: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	salt, err := makeSalt(cfg.SaltSize)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания соли: %w", err)
	}

	key, err := crypto.DeriveKey(crypto.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       cfg.Time,
		Memory:     cfg.Memory,
		Threads:    cfg.Threads,
		KeyLen:     cfg.KeyLen,
	})
	if err != nil {
		return nil, fmt.Errorf("ошибка создания ключа: %w", err)
	}

	crypter, err := crypto.MakeCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	nonce, err := crypto.MakeNonce(crypter)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	encryptedData := crypter.Seal(nil, nonce, privateKeyBytes, nil)

	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedData,
		Headers: map[string]string{
			"Nonce":   base64.StdEncoding.EncodeToString(nonce),
			"Salt":    base64.StdEncoding.EncodeToString(salt),
			"KDF":     "Argon2",
			"Time":    strconv.FormatUint(uint64(cfg.Time), 10),
			"Memory":  strconv.FormatUint(uint64(cfg.Memory), 10),
			"Threads": strconv.FormatUint(uint64(cfg.Threads), 10),
			"KeyLen":  strconv.FormatUint(uint64(cfg.KeyLen), 10),
		},
	}

	if err = savePrivateKeyToPEM(absPath, block); err != nil {
		return nil, fmt.Errorf("ошибка сохранения приватного ключа в файл .pem: %w", err)
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
