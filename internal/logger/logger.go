package logger

import (
	"log"
)

var (
	LogProxy  *log.Logger
	ErrLog    *log.Logger
	LogTarget *log.Logger
)

// Config 日志配置
type Config struct {
	Level          string
	DisableConsole bool
	File           string
}

// LogInfo 记录普通日志
func LogInfo(format string, args ...interface{}) {
	if LogTarget != nil {
		LogTarget.Printf(format, args...)
	}
}

// LogError 记录错误日志
func LogError(format string, args ...interface{}) {
	if ErrLog != nil {
		ErrLog.Printf(format, args...)
	}
}

// LogStats 记录统计信息
func LogStats(format string, args ...interface{}) {
	if LogProxy != nil {
		LogProxy.Printf(format, args...)
	}
}
