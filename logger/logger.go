package logger

import (
	"io"
	"log"
	"os"
)

type Logger interface {
	Info(v ...any)
	Warn(v ...any)
	Error(v ...any)
}

type FileLogger struct {
	file   *os.File
	logger *log.Logger
}

func New(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	mw := io.MultiWriter(os.Stdout, f)

	return &FileLogger{
		file:   f,
		logger: log.New(mw, "", log.Ldate|log.Ltime),
	}, nil
}

func (l *FileLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *FileLogger) Info(v ...any) {
	l.logger.Println(append([]any{"INFO:"}, v...)...)
}

func (l *FileLogger) Warn(v ...any) {
	l.logger.Println(append([]any{"WARN:"}, v...)...)
}

func (l *FileLogger) Error(v ...any) {
	l.logger.Println(append([]any{"ERROR:"}, v...)...)
}
