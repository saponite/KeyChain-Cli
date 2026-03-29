package terminal

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

func GetPassphrase() (pass []byte, err error) {
	fmt.Println("Введите секретную фразу: ")
	fd := int(os.Stdin.Fd())

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания скрытого терминала: %w", err)
	}

	defer func() {
		if restoreErr := term.Restore(fd, oldState); restoreErr != nil && err == nil {
			err = fmt.Errorf("ошибка возврата терминала: %w", restoreErr)
		}
	}()

	pass, err = term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("ошибка возврата терминала: %w", err)
	}

	fmt.Println()

	return pass, nil
}

func ProcessFilePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("ошибка конвертации в абсолютный путь: %q", err)
	}

	fileInfo, err := os.Stat(absolutePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("путь '%s' не существует", path)
		}
		return "", fmt.Errorf("информация об ошибке: %v", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("путь '%s' не указывает на файл", path)
	}

	return absolutePath, nil
}
