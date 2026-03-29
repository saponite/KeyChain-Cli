package utils

import (
	"fmt"
	"os"

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
