package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	// 全局logger实例
	attackLogger  *log.Logger
	errorLogger   *log.Logger
	metricsLogger *log.Logger
	debugLogger   *log.Logger

	// 确保只初始化一次
	once sync.Once
)

// LogConfig 日志配置
type LogConfig struct {
	LogDir     string
	Debug      bool
	MaxSize    int64 // 单个日志文件最大大小（MB）
	MaxBackups int   // 最大保留文件数
}

// InitLogger 初始化日志系统
func InitLogger(config LogConfig) error {
	var err error
	once.Do(func() {
		err = initLoggers(config)
	})
	return err
}

func initLoggers(config LogConfig) error {
	// 创建日志目录
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// 创建各类日志文件
	attackFile, err := createLogFile(filepath.Join(config.LogDir, "attack.log"))
	if err != nil {
		return err
	}

	errorFile, err := createLogFile(filepath.Join(config.LogDir, "error.log"))
	if err != nil {
		return err
	}

	metricsFile, err := createLogFile(filepath.Join(config.LogDir, "metrics.log"))
	if err != nil {
		return err
	}

	// 初始化loggers
	attackLogger = log.New(io.MultiWriter(os.Stdout, attackFile),
		"ATTACK: ",
		log.Ldate|log.Ltime|log.Lmicroseconds)

	errorLogger = log.New(io.MultiWriter(os.Stderr, errorFile),
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)

	metricsLogger = log.New(metricsFile,
		"METRICS: ",
		log.Ldate|log.Ltime|log.Lmicroseconds)

	if config.Debug {
		debugLogger = log.New(os.Stdout,
			"DEBUG: ",
			log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	}

	return nil
}

func createLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}

// LogAttack 记录攻击日志
func LogAttack(format string, v ...interface{}) {
	if attackLogger != nil {
		attackLogger.Printf(format, v...)
	}
}

// LogError 记录错误日志
func LogError(format string, v ...interface{}) {
	if errorLogger != nil {
		errorLogger.Printf(format, v...)
	}
}

// LogMetrics 记录指标日志
func LogMetrics(format string, v ...interface{}) {
	if metricsLogger != nil {
		metricsLogger.Printf(format, v...)
	}
}

// LogDebug 记录调试日志
func LogDebug(format string, v ...interface{}) {
	if debugLogger != nil {
		debugLogger.Printf(format, v...)
	}
}

// 日志轮转
type logRotator struct {
	file       *os.File
	maxSize    int64
	maxBackups int
}

func (r *logRotator) Write(p []byte) (n int, err error) {
	if r.file == nil {
		return 0, fmt.Errorf("log file is nil")
	}

	// 检查文件大小
	info, err := r.file.Stat()
	if err != nil {
		return 0, err
	}

	if info.Size()+int64(len(p)) > r.maxSize*1024*1024 {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}

	return r.file.Write(p)
}

func (r *logRotator) rotate() error {
	// 关闭当前文件
	if err := r.file.Close(); err != nil {
		return err
	}

	// 重命名为备份文件
	timestamp := time.Now().Format("20060102150405")
	backupName := fmt.Sprintf("%s.%s", r.file.Name(), timestamp)
	if err := os.Rename(r.file.Name(), backupName); err != nil {
		return err
	}

	// 创建新文件
	newFile, err := os.OpenFile(r.file.Name(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	r.file = newFile

	// 清理旧文件
	return r.cleanup()
}

func (r *logRotator) cleanup() error {
	dir := filepath.Dir(r.file.Name())
	pattern := filepath.Base(r.file.Name()) + ".*"

	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}

	if len(files) <= r.maxBackups {
		return nil
	}

	// 按时间排序并删除最旧的文件
	// TODO: 实现文件排序和删除逻辑

	return nil
}
