package logger

import (
	"log"
	"os"
)

type Logger interface {
	Info(v ...any)
	Warn(v ...any)
	Error(v ...any)
	Print(v ...any)
}

type FileLogger struct {
	file       *os.File
	fileLogger *log.Logger
	termLogger *log.Logger
}

func New(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &FileLogger{
		file:       f,
		fileLogger: log.New(f, "", log.Ldate|log.Ltime),
		termLogger: log.New(os.Stdout, "", 0),
	}, nil
}

func (l *FileLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *FileLogger) Info(v ...any) {
	l.fileLogger.Println(append([]any{"INFO:"}, v...)...)
}

func (l *FileLogger) Warn(v ...any) {
	l.fileLogger.Println(append([]any{"WARN:"}, v...)...)
}

func (l *FileLogger) Error(v ...any) {
	l.fileLogger.Println(append([]any{"ERROR:"}, v...)...)
}

func (l *FileLogger) Print(v ...any) {
	l.termLogger.Println(v...)
}
