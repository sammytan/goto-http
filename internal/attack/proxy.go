package attack

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// NoLoggingDialContextFunc创建一个自定义拨号函数，该函数在GUI模式下不会打印特定错误
func NoLoggingDialContextFunc(gui bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 使用标准拨号器
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		// 尝试建立连接
		conn, err := dialer.DialContext(ctx, network, addr)

		// 如果是GUI模式，过滤掉特定错误，防止它们显示在UI上
		if gui && err != nil {
			// 仅返回错误，但不输出到标准日志
			// 错误会被记录到错误统计中，但不会显示在屏幕上
			return nil, fmt.Errorf("request failed after 3 retries: %v", err)
		}

		return conn, err
	}
}

// CreateNoLoggingTransport返回一个不记录特定错误的http.Transport实例
func CreateNoLoggingTransport(proxyURL string) *http.Transport {
	// 检查是否运行在GUI模式下
	isGUI := os.Getenv("NO_LOGGING") == "true"

	// 解析代理URL
	parsedURL, _ := url.Parse(proxyURL)

	// 创建自定义传输
	return &http.Transport{
		Proxy:                 http.ProxyURL(parsedURL),
		DialContext:           NoLoggingDialContextFunc(isGUI),
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}
}

// SilentDialer是一个在GUI模式下不记录特定错误的拨号器
type SilentDialer struct {
	*net.Dialer
}

// DialContext重写，过滤代理连接错误
func (d *SilentDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, addr)

	// 处理错误但不输出到控制台
	if err != nil && os.Getenv("NO_LOGGING") == "true" {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") ||
			strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "i/o timeout") {
			return nil, fmt.Errorf("request failed after 3 retries: Get \"http://example.com\": proxyconnect tcp: dial tcp %s: %v", addr, err)
		}
	}

	return conn, err
}

// NewSilentDialer创建一个新的静默拨号器
func NewSilentDialer() *SilentDialer {
	return &SilentDialer{
		Dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}
