package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type KeyDerivationConfig struct {
	Passphrase           []byte
	Salt                 []byte
	Time, Memory, KeyLen uint32
	Threads              uint8
}

func MakeNonce(crypter cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, crypter.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать одноразовую фразу (nonce): %w", err)
	}

	return nonce, nil
}

func MakeCrypter(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать блок шифрования: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать шифр GCM: %w", err)
	}

	return gcm, nil
}

func DeriveKey(config KeyDerivationConfig) ([]byte, error) {
	if len(config.Passphrase) == 0 || len(config.Salt) == 0 {
		return nil, fmt.Errorf("секретная фраза и соль пусты")
	}

	return argon2.IDKey(config.Passphrase, config.Salt, config.Time, config.Memory, config.Threads, config.KeyLen), nil
}
