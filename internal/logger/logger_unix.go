//go:build linux || darwin

package logger

import (
	"io"
	"log"
	"os"
)

// InitLogger 初始化日志系统
func InitLogger(config *Config) error {
	if config == nil {
		config = &Config{
			Level:          "info",
			DisableConsole: false,
			File:           "logs/app.log",
		}
	}

	var writer io.Writer = os.Stdout

	if config.File != "" {
		if err := os.MkdirAll("logs", 0755); err != nil {
			return err
		}

		logFile, err := os.OpenFile(config.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}

		if !config.DisableConsole {
			writer = io.MultiWriter(os.Stdout, logFile)
		} else {
			writer = logFile
		}
	}

	// 直接赋值给包级别的变量
	LogProxy = log.New(writer, "[PROXY] ", log.Ldate|log.Ltime|log.Lmicroseconds)
	ErrLog = log.New(writer, "[ERROR] ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	LogTarget = log.New(writer, "[TARGET] ", log.Ldate|log.Ltime|log.Lmicroseconds)

	return nil
}
