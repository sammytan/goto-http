package errors

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ErrorType 错误类型
type ErrorType string

const (
	NETWORK_ERROR    ErrorType = "network_error"
	PROXY_ERROR      ErrorType = "proxy_error"
	TIMEOUT_ERROR    ErrorType = "timeout_error"
	VALIDATION_ERROR ErrorType = "validation_error"
	RATE_LIMIT_ERROR ErrorType = "rate_limit_error"
	BYPASS_ERROR     ErrorType = "bypass_error"
	UNEXPECTED_ERROR ErrorType = "unexpected_error"
)

// Error 自定义错误
type Error struct {
	Type      ErrorType              `json:"type"`
	Message   string                 `json:"message"`
	Code      int                    `json:"code"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Stack     string                 `json:"stack,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Error 实现error接口
func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s (Code: %d)", e.Type, e.Message, e.Code)
}

// Handler 错误处理器
type Handler struct {
	mu       sync.RWMutex
	errors   []*Error
	handlers map[ErrorType]func(*Error)
	maxSize  int
}

// NewHandler 创建新的错误处理器
func NewHandler(maxSize int) *Handler {
	return &Handler{
		errors:   make([]*Error, 0),
		handlers: make(map[ErrorType]func(*Error)),
		maxSize:  maxSize,
	}
}

// NewError 创建新的错误
func NewError(errType ErrorType, message string, code int) *Error {
	var stack strings.Builder
	for i := 1; i < 5; i++ { // 获取调用栈
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fn := runtime.FuncForPC(pc)
		stack.WriteString(fmt.Sprintf("\n\t%s:%d %s", file, line, fn.Name()))
	}

	return &Error{
		Type:      errType,
		Message:   message,
		Code:      code,
		Details:   make(map[string]interface{}),
		Stack:     stack.String(),
		Timestamp: time.Now(),
	}
}

// Handle 处理错误
func (h *Handler) Handle(err error) {
	if err == nil {
		return
	}

	var customErr *Error
	switch e := err.(type) {
	case *Error:
		customErr = e
	default:
		customErr = NewError(UNEXPECTED_ERROR, err.Error(), 500)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// 添加错误到列表
	h.errors = append(h.errors, customErr)
	if len(h.errors) > h.maxSize {
		h.errors = h.errors[1:]
	}

	// 调用对应的处理函数
	if handler, ok := h.handlers[customErr.Type]; ok {
		handler(customErr)
	}
}

// RegisterHandler 注册错误处理函数
func (h *Handler) RegisterHandler(errType ErrorType, handler func(*Error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers[errType] = handler
}

// GetErrors 获取错误列表
func (h *Handler) GetErrors(errType ErrorType) []*Error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if errType == "" {
		result := make([]*Error, len(h.errors))
		copy(result, h.errors)
		return result
	}

	result := make([]*Error, 0)
	for _, err := range h.errors {
		if err.Type == errType {
			result = append(result, err)
		}
	}
	return result
}

// ClearErrors 清除错误
func (h *Handler) ClearErrors(errType ErrorType) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if errType == "" {
		h.errors = make([]*Error, 0)
		return
	}

	newErrors := make([]*Error, 0)
	for _, err := range h.errors {
		if err.Type != errType {
			newErrors = append(newErrors, err)
		}
	}
	h.errors = newErrors
}

// Export 导出错误日志
func (h *Handler) Export() ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return json.Marshal(h.errors)
}

// IsErrorType 检查错误类型
func IsErrorType(err error, errType ErrorType) bool {
	if customErr, ok := err.(*Error); ok {
		return customErr.Type == errType
	}
	return false
}

// WithDetails 添加错误详情
func (e *Error) WithDetails(details map[string]interface{}) *Error {
	e.Details = details
	return e
}

// GetErrorStats 获取错误统计信息
func (h *Handler) GetErrorStats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := make(map[string]interface{})
	typeCounts := make(map[ErrorType]int)

	for _, err := range h.errors {
		typeCounts[err.Type]++
	}

	stats["total"] = len(h.errors)
	stats["by_type"] = typeCounts

	if len(h.errors) > 0 {
		stats["latest"] = h.errors[len(h.errors)-1]
	}

	return stats
}
