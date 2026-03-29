# KeyChain-Cli

Данный проект содержит в себе исходные файлы утилиту CLI для шифрования данных,
точнее для генерации и управления RSA-ключами с безопасным хранением закрытых 
ключей в зашифрованных PEM-файлах, а также подписания файлов с помощью закрытого ключа.

Используется [Argon2](https://ru.wikipedia.org/wiki/Argon2) для деривации ключей и AES для шифрования, для намеренного 
замедления хеширования; [AES](https://ru.wikipedia.org/wiki/AES_(%D1%81%D1%82%D0%B0%D0%BD%D0%B4%D0%B0%D1%80%D1%82_%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F)) используется для шифрования закрытого ключа; соль (Salt) размером 16 байт генерируется 
автоматически при каждом запуске программы.

## Особенности:

- генерация пары RSA-ключей (закрытый + открытый);
- закрытый ключ шифруется AES-GCM с ключом, полученным через Argon2id;
- соль и nonce сохраняются в заголовках PEM-файла;
- настраиваемые параметры Argon2 (time, memory, threads, keyLen) через CLI или yaml. [Подробнее](https://pkg.go.dev/golang.org/x/crypto@v0.49.0/argon2) о параметрах;
- приоритет параметров: флаги CLI, config.yaml, значения по умолчанию;
- реализован собственный логгер с раздельным выводом в терминал и app.log файл;
- CLI через [Cobra](https://github.com/spf13/cobra), конфигурация через [Viper](https://github.com/spf13/viper);
- логгер передаётся через DI;
- подписание файлов с помощью закрытого ключа RSA-PSS + SHA3-256;
- подпись сохраняется в .sig файл рядом с исходным файлом.

## Требования:
- [Go](https://go.dev/doc/install) 1.21+;
- Linux / macOS / Windows. Протестировано на Linux, macOS.

## Установка.

### Склонируйте репозиторий.
```bash
git clone https://github.com/saponite/KeyChain-Cli.git
cd KeyChain-CLI
```

### Скомпилируйте программу.
```bash
go build main.go
```

### Запустите полученный бинарный файл.
```bash
./main keys generate --time 1 --memory 64 --threads 4 --keyLen 32 --private-key-path priv_key.pem --public-key-path pub_key.pem --private-key-size 2048 --salt-size 16
```
или
```bash
./main keys generate 
```

Иной вариант запуска программы без предварительной компиляции.
```bash
go run . keys generate --time 1 --memory 64 --threads 4 --keyLen 32 --private-key-path priv_key.pem --public-key-path pub_key.pem --private-key-size 2048 --salt-size 16
```

### Значения ключей.
```
-h, --help                      help for generate
    --keyLen uint32             Длина ключа (в байтах). (default 32)
    --memory uint32             Количество памяти для генерации ключа (в мегабайтах). (default 65536)
    --private-key-path string   Путь для сохранения закрытого ключа. (default "priv_key.pem")
    --private-key-size int      Размер закрытого ключа в битах. (default 2048)
    --public-key-path string    Путь для сохранения открытого ключа. (default "pub_key.pem")
    --salt-size int             Размер соли, используемый при выводе ключа, в байтах. (default 16)
    --threads uint8             Количество потоков, которые нужно задействовать для генерации ключа. (default 4)
    --time uint32               Время генерации ключа. (default 1)
```

### Подписание файла.
```bash
./main signatures sign --file-path file.txt --signer-id "John"
```
или с указанием пути к ключу:
```bash
./main signatures sign --file-path file.txt --signer-id "John" --private-key-path priv_key.pem
```

### Значения ключей для sign.
```
-h, --help                      help for sign
    --file-path string          Путь к файлу для подписи.
    --private-key-path string   Путь к закрытому ключу. (default "priv_key.pem")
    --signer-id string          Имя или идентификатор подписанта.
```

### Лицензия.

[MIT License](LICENSE)
