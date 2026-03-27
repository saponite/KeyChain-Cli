package cryptoUtils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type KeyDerivationConfig struct {
	Passphrase []byte
	Salt       []byte
}

func MakeNonce(crypter cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, crypter.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать одноразовую фразу (nonce): %v", err)
	}

	return nonce, nil
}

func MakeCrypter(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать блок шифрования: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать шифр GCMr: %v", err)
	}

	return gcm, nil
}

func DeriveKey(config KeyDerivationConfig) ([]byte, error) {
	if len(config.Passphrase) == 0 || len(config.Salt) == 0 {
		return nil, fmt.Errorf("секретная фраза и соль пусты")
	}

	return argon2.IDKey(config.Passphrase, config.Salt, 1, 64*1024, 4, 32), nil
}
