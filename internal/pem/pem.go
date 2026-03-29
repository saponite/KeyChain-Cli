package pem

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
)

type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func DecodeFile(path string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать PEM-файл: %w", err)
	}

	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return nil, errors.New("не удалось декодировать PEM-блок")
	}

	if len(rest) > 0 {
		return nil, errors.New("PEM-файл содержит лишние данные после блока")
	}

	return block, nil
}

func GetSaltAndNonce(block *pem.Block) (nonce, salt []byte, err error) {
	nonceB64, ok := block.Headers["Nonce"]
	if !ok {
		return nil, nil, errors.New("nonce не найден в заголовках PEM")
	}

	saltB64, ok := block.Headers["Salt"]
	if !ok {
		return nil, nil, errors.New("salt не найден в заголовках PEM")
	}

	nonce, err = base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка декодирования nonce: %w", err)
	}

	salt, err = base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка декодирования salt: %w", err)
	}

	return nonce, salt, nil
}

func GetKDFParams(block *pem.Block) (KDFParams, error) {
	parse := func(key string) (uint64, error) {
		val, ok := block.Headers[key]
		if !ok {
			return 0, fmt.Errorf("параметр '%s' не найден в заголовках PEM", key)
		}
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("ошибка парсинга параметра '%s': %w", key, err)
		}

		return n, nil
	}

	time, err := parse("Time")
	if err != nil {
		return KDFParams{}, err
	}
	memory, err := parse("Memory")
	if err != nil {
		return KDFParams{}, err
	}
	threads, err := parse("Threads")
	if err != nil {
		return KDFParams{}, err
	}
	keyLen, err := parse("KeyLen")
	if err != nil {
		return KDFParams{}, err
	}

	return KDFParams{
		Time:    uint32(time),
		Memory:  uint32(memory),
		Threads: uint8(threads),
		KeyLen:  uint32(keyLen),
	}, nil
}
