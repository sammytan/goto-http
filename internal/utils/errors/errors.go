package errors

import (
	"fmt"
	"runtime"
	"time"
)

// ErrorType 错误类型
type ErrorType int

const (
	NetworkError ErrorType = iota
	ProxyError
	ResourceError
	ProtocolError
	ConfigError
	SystemError
)

// Error 自定义错误结构
type Error struct {
	Type    ErrorType
	Message string
	Cause   error
	Stack   string
	Time    time.Time
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// NewError 创建新错误
func NewError(errType ErrorType, message string, cause error) *Error {
	stack := getStack()
	return &Error{
		Type:    errType,
		Message: message,
		Cause:   cause,
		Stack:   stack,
		Time:    time.Now(),
	}
}

// getStack 获取堆栈信息
func getStack() string {
	var buf [4096]byte
	n := runtime.Stack(buf[:], false)
	return string(buf[:n])
}

// IsNetworkError 判断是否为网络错误
func IsNetworkError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Type == NetworkError
	}
	return false
}

// IsProxyError 判断是否为代理错误
func IsProxyError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Type == ProxyError
	}
	return false
}

// IsResourceError 判断是否为资源错误
func IsResourceError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Type == ResourceError
	}
	return false
}

// ErrorHandler 错误处理器
type ErrorHandler struct {
	maxRetries int
	retryDelay time.Duration
}

// NewErrorHandler 创建错误处理器
func NewErrorHandler(maxRetries int, retryDelay time.Duration) *ErrorHandler {
	return &ErrorHandler{
		maxRetries: maxRetries,
		retryDelay: retryDelay,
	}
}

// HandleError 处理错误
func (h *ErrorHandler) HandleError(err error, retryFunc func() error) error {
	if err == nil {
		return nil
	}

	// 获取错误类型
	var errType ErrorType
	if e, ok := err.(*Error); ok {
		errType = e.Type
	} else {
		errType = SystemError
	}

	// 根据错误类型处理
	switch errType {
	case NetworkError:
		return h.handleNetworkError(err, retryFunc)
	case ProxyError:
		return h.handleProxyError(err, retryFunc)
	case ResourceError:
		return h.handleResourceError(err)
	case ProtocolError:
		return h.handleProtocolError(err, retryFunc)
	default:
		return h.handleSystemError(err)
	}
}

// handleNetworkError 处理网络错误
func (h *ErrorHandler) handleNetworkError(err error, retryFunc func() error) error {
	for i := 0; i < h.maxRetries; i++ {
		if err = retryFunc(); err == nil {
			return nil
		}
		time.Sleep(h.retryDelay)
	}
	return NewError(NetworkError, "max retries exceeded", err)
}

// handleProxyError 处理代理错误
func (h *ErrorHandler) handleProxyError(err error, retryFunc func() error) error {
	// TODO: 实现代理切换逻辑
	return NewError(ProxyError, "proxy error handling not implemented", err)
}

// handleResourceError 处理资源错误
func (h *ErrorHandler) handleResourceError(err error) error {
	// TODO: 实现资源释放逻辑
	return NewError(ResourceError, "resource error handling not implemented", err)
}

// handleProtocolError 处理协议错误
func (h *ErrorHandler) handleProtocolError(err error, retryFunc func() error) error {
	// TODO: 实现协议降级逻辑
	return NewError(ProtocolError, "protocol error handling not implemented", err)
}

// handleSystemError 处理系统错误
func (h *ErrorHandler) handleSystemError(err error) error {
	// TODO: 实现系统错误恢复逻辑
	return NewError(SystemError, "system error handling not implemented", err)
}

// ErrorRecovery 错误恢复函数
func ErrorRecovery(handler func(interface{})) {
	if r := recover(); r != nil {
		stack := getStack()
		err := NewError(SystemError, fmt.Sprintf("panic recovered: %v", r), nil)
		err.Stack = stack
		handler(err)
	}
}
