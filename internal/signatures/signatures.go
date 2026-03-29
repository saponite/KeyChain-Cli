package signatures

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	internalcrypto "KeyChain-CLI/internal/crypto"
	internalpem "KeyChain-CLI/internal/pem"
	"KeyChain-CLI/terminal"

	"golang.org/x/crypto/sha3"
)

const (
	minSignerInfoLength = 1
	maxSignerInfoLength = 2<<15 - 1
)

func ValidateSignerID(signerID string) error {
	if len(signerID) < minSignerInfoLength || len(signerID) > maxSignerInfoLength {
		return fmt.Errorf("signer-id должен быть от %d до %d символов", minSignerInfoLength, maxSignerInfoLength)
	}
	return nil
}

func SignFile(privateKeyPath, filePath, signerID string) error {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("ошибка загрузки закрытого ключа: %w", err)
	}

	digest, err := hashFile(filePath)
	if err != nil {
		return fmt.Errorf("ошибка хеширования файла: %w", err)
	}

	signature, err := signDigest(digest, privateKey)
	if err != nil {
		return fmt.Errorf("ошибка подписания: %w", err)
	}

	signaturePackage, err := makeSignaturePackage(signature, signerID)
	if err != nil {
		return fmt.Errorf("ошибка создания пакета подписи: %w", err)
	}

	if err = writeSignatureToFile(signaturePackage, filePath); err != nil {
		return fmt.Errorf("ошибка записи подписи: %w", err)
	}

	return nil
}

func VerifyFile(pubKeyPath, filePath string) ([]byte, error) {
	publicKey, err := loadPublicKey(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки публичного ключа: %w", err)
	}

	digest, err := hashFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("ошибка хеширования файла: %w", err)
	}

	signatureRaw, err := readSignature(filePath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения подписи: %w", err)
	}

	signerInfo, err := verifyFileSignature(publicKey, digest, signatureRaw)
	if err != nil {
		return nil, fmt.Errorf("ошибка проверки подписи: %w", err)
	}

	return signerInfo, nil
}

func loadPrivateKey(pkPath string) (*rsa.PrivateKey, error) {
	block, err := internalpem.DecodeFile(pkPath)
	if err != nil {
		return nil, err
	}

	nonce, salt, err := internalpem.GetSaltAndNonce(block)
	if err != nil {
		return nil, err
	}

	kdfParams, err := internalpem.GetKDFParams(block)
	if err != nil {
		return nil, err
	}

	passphrase, err := terminal.GetPassphrase()
	if err != nil {
		return nil, err
	}

	key, err := internalcrypto.DeriveKey(internalcrypto.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       kdfParams.Time,
		Memory:     kdfParams.Memory,
		Threads:    kdfParams.Threads,
		KeyLen:     kdfParams.KeyLen,
	})
	if err != nil {
		return nil, fmt.Errorf("ошибка получения ключа: %w", err)
	}

	crypter, err := internalcrypto.MakeCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания шифра: %w", err)
	}

	plaintext, err := crypter.Open(nil, nonce, block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки закрытого ключа: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга закрытого ключа: %w", err)
	}

	return privateKey, nil
}

func hashFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл: %w", err)
	}
	defer file.Close()

	hasher := sha3.New256()
	if _, err = io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("ошибка хеширования файла: %w", err)
	}

	return hasher.Sum(nil), nil
}

func signDigest(digest []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA3_256, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("не удалось подписать дайджест: %w", err)
	}

	return signature, nil
}

func makeSignaturePackage(signature []byte, signerInfo string) ([]byte, error) {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, uint32(len(signerInfo))); err != nil {
		return nil, fmt.Errorf("не удалось записать длину signer info: %w", err)
	}

	if _, err := buf.WriteString(signerInfo); err != nil {
		return nil, fmt.Errorf("не удалось записать signer info: %w", err)
	}

	if _, err := buf.Write(signature); err != nil {
		return nil, fmt.Errorf("не удалось записать подпись: %w", err)
	}

	return buf.Bytes(), nil
}

func writeSignatureToFile(signaturePackage []byte, initialFilePath string) error {
	sigFilePath := filepath.Join(filepath.Dir(initialFilePath), filepath.Base(initialFilePath)+".sig")
	if err := os.WriteFile(sigFilePath, signaturePackage, 0644); err != nil {
		return fmt.Errorf("ошибка записи подписи в файл: %w", err)
	}

	return nil
}

func readSignature(initialFilePath string) ([]byte, error) {
	dir := filepath.Dir(initialFilePath)
	baseName := filepath.Base(initialFilePath)

	sigFilePath := filepath.Join(dir, baseName+".sig")

	return os.ReadFile(sigFilePath)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := internalpem.DecodeFile(path)
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга публичного ключа: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("файл не содержит RSA публичный ключ")
	}

	return rsaPub, nil
}

func verifyFileSignature(publicKey *rsa.PublicKey, digest []byte, signatureRaw []byte) ([]byte, error) {
	buf := bytes.NewReader(signatureRaw)

	var nameLength uint32
	if err := binary.Read(buf, binary.BigEndian, &nameLength); err != nil {
		return nil, fmt.Errorf("failed to read signer info length: %v", err)
	}

	signerInfo := make([]byte, nameLength)
	if _, err := buf.Read(signerInfo); err != nil {
		return nil, fmt.Errorf("failed to read signer info: %v", err)
	}

	signature := make([]byte, buf.Len())
	if _, err := buf.Read(signature); err != nil {
		return nil, fmt.Errorf("failed to read signature: %v", err)
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	if err := rsa.VerifyPSS(publicKey, crypto.SHA3_256, digest, signature, opts); err != nil {
		return nil, fmt.Errorf("signature verification failed: %v", err)
	}

	return signerInfo, nil
}
