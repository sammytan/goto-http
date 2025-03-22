package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	httplib "goto-http/pkg/protocol/http"
	"net/http"

	"goto-http/pkg/random"

	"github.com/gorilla/websocket"
)

// Manager manages a pool of proxies
type Manager struct {
	config             *Config
	proxies            []*Proxy
	client             *http.Client
	mu                 sync.RWMutex
	minProxies         int
	validateQueue      chan *Proxy
	validateDone       chan bool
	validateContext    context.Context
	validateCancelFunc context.CancelFunc
	debugEnabled       bool
	// server模式相关字段
	serverProviders []Provider // 保存server模式的代理提供者信息
	ctx             context.Context
	cancel          context.CancelFunc
	maxFails        int
	retryInterval   time.Duration
	pools           []*ProxyPool
	validator       *Validator
	rng             *rand.Rand    // Dedicated random number generator
	refreshChan     chan struct{} // 刷新代理的通道
	usedProxies     sync.Map      // 记录最近使用过的代理
	proxyTimeout    time.Duration // 代理重用超时时间
	isRefreshing    atomic.Bool   // 标记是否正在刷新代理列表
	lastRefreshTime atomic.Value  // 记录上次刷新时间
	sessionID       string
	refreshInterval time.Duration // 代理刷新间隔
	lastProxyIndex  int           // 记录上次使用的代理索引
}

// validateManagerConfig validates the manager configuration
func validateManagerConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if config.Type == "" {
		return fmt.Errorf("proxy type must be specified")
	}

	switch config.Type {
	case TYPE_NONE:
		return nil
	case TYPE_FILE:
		if config.File == "" {
			return fmt.Errorf("file path is required for file proxy type")
		}
	case TYPE_API:
		if len(config.Providers) == 0 {
			return fmt.Errorf("no proxy providers configured for API type")
		}
	case TYPE_SERVER:
		if len(config.Providers) == 0 {
			return fmt.Errorf("no proxy providers configured for server type")
		}
	default:
		return fmt.Errorf("invalid proxy type: %s", config.Type)
	}

	return nil
}

// NewManager creates a new proxy manager
func NewManager(config *Config) (*Manager, error) {
	fmt.Printf("Initializing Manager with config: %+v\n", config) // Debug log
	if err := validateManagerConfig(config); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create HTTP client
	timeout := time.Duration(config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	// 设置最大连接数和每个主机的最大连接数
	maxConns := config.MaxConns
	if maxConns == 0 {
		maxConns = 100 // 默认值
	}

	maxConnsPerHost := config.MaxConnsPerHost
	if maxConnsPerHost == 0 {
		maxConnsPerHost = 100 // 默认值
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        maxConns,
			MaxConnsPerHost:     maxConnsPerHost,
			MaxIdleConnsPerHost: -1,
		},
	}

	interval := time.Duration(config.RetryInterval) * time.Second
	if interval == 0 {
		interval = time.Minute
	}

	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	m := &Manager{
		config:          config,
		ctx:             ctx,
		cancel:          cancel,
		maxFails:        config.MaxFails,
		retryInterval:   interval,
		client:          client,
		pools:           make([]*ProxyPool, 0),
		rng:             rng,
		minProxies:      50, // Default minimum proxies
		refreshChan:     make(chan struct{}, 1),
		serverProviders: make([]Provider, 0), // 保存server模式的代理提供者信息
		proxyTimeout:    5 * time.Minute,
		validator: &Validator{
			URL:     config.ValidateURL,
			Timeout: timeout,
			Client:  client,
		},
		lastProxyIndex: 0,
	}

	m.lastRefreshTime.Store(time.Now())

	// 从配置中获取刷新间隔
	if len(config.Providers) > 0 {
		provider := &config.Providers[0]
		if provider.Enable && provider.Params.TimeVal > 0 {
			m.refreshInterval = time.Duration(provider.Params.TimeVal) * time.Second
		} else {
			m.refreshInterval = 30 * time.Second // 默认30秒
		}
	}

	// Start proxy pool maintenance goroutine
	if config.Type == TYPE_API {
		go m.maintainAPIProxyPool()
	}

	// Load proxies based on configuration type
	switch config.Type {
	case TYPE_NONE:
		// No proxies needed
		return m, nil

	case TYPE_FILE:
		if err := m.loadProxiesFromFile(); err != nil {
			cancel()
			return nil, err
		}

	case TYPE_API:
		// 处理API提供者
		if err := m.loadProxiesFromAPI(); err != nil {
			cancel()
			return nil, err
		}

	case TYPE_SERVER:
		// 处理SERVER提供者
		if err := m.loadProxiesFromServer(); err != nil {
			cancel()
			return nil, err
		}
	}

	// 根据不同模式决定是否需要初始化providers
	if config.Type == TYPE_API || config.Type == TYPE_SERVER {
		for _, provider := range config.Providers {
			if err := m.loadProxiesFromProvider(&provider); err != nil {
				return nil, fmt.Errorf("failed to load proxies from provider: %v", err)
			}
		}
	}

	// 确保加载了足够的代理
	if m.config.Type == TYPE_SERVER {
		// SERVER模式下检查服务器提供者是否存在
		if len(m.serverProviders) == 0 {
			cancel()
			return nil, fmt.Errorf("no server providers available after initialization")
		}
	} else if len(m.proxies) == 0 {
		// 其他模式下检查代理列表是否为空
		cancel()
		return nil, fmt.Errorf("no proxies available after initialization")
	}

	// 启动清理goroutine
	go m.cleanupUsedProxies()

	return m, nil
}

// loadProxiesFromFile loads proxies from file providers
func (m *Manager) loadProxiesFromFile() error {
	if m.config.File == "" {
		return fmt.Errorf("no file providers configured")
	}

	uniqueProxies := make(map[string]bool)
	var newProxies []*Proxy
	var loadErrors []error

	for _, provider := range m.config.Providers {
		if !provider.Enable {
			continue
		}

		// 使用provider.Name作为文件路径,因为Provider结构体中没有Path字段
		filePath := m.config.File // 直接使用配置中的文件路径
		if filePath == "" {
			return fmt.Errorf("node path is empty for provider %s", provider.Name)
		}
		if m.config.ValidateEnable {
			fmt.Printf("[DEBUG] 从文件加载代理: %s\n", filePath)
		}

		// 读取文件内容
		data, err := os.ReadFile(filePath)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("provider %s: failed to read file %s: %v", provider.Name, filePath, err))
			continue
		}

		// 按行分割文件内容
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue // 跳过空行和注释行
			}

			// 确保代理URL有协议前缀
			proxyURL := line
			if !strings.HasPrefix(strings.ToLower(proxyURL), "http://") && !strings.HasPrefix(strings.ToLower(proxyURL), "https://") {
				proxyURL = "http://" + proxyURL
			}

			// 解析代理地址并提取主机名
			parsedURL, err := url.Parse(proxyURL)
			if err != nil {
				continue
			}

			// 如果这个代理地址已经存在，跳过
			if uniqueProxies[proxyURL] {
				continue
			}

			// 记录完整代理地址
			uniqueProxies[proxyURL] = true

			newProxies = append(newProxies, &Proxy{
				URL:      proxyURL,
				Protocol: "http",
				Type:     TYPE_HTTP,
				Host:     parsedURL.Hostname(),
				Country:  provider.GetCountry(),
				LastUsed: time.Now(),
			})

			if m.config.ValidateEnable && len(newProxies) < 5 {
				fmt.Printf("[DEBUG] 添加代理: %s\n", proxyURL)
			}
		}

		if m.config.ValidateEnable {
			fmt.Printf("[DEBUG] 从文件 %s 加载了 %d 个代理\n", filePath, len(newProxies))
		}
	}

	// 更新代理列表
	m.mu.Lock()
	m.proxies = newProxies
	proxyCount := len(m.proxies)
	m.mu.Unlock()

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] 最终从文件加载了 %d 个代理\n", proxyCount)
	}

	// 如果没有获取到足够的代理，返回错误
	if proxyCount < m.minProxies {
		return fmt.Errorf("insufficient proxies from file: got %d, need %d", proxyCount, m.minProxies)
	}

	if len(loadErrors) > 0 {
		// Log the errors
		for _, err := range loadErrors {
			fmt.Printf("[ERROR] %v\n", err)
		}
		// Or return a combined error
		return fmt.Errorf("encountered %d errors: %v", len(loadErrors), loadErrors[0])
	}

	return nil
}

// loadProxiesFromAPI loads proxies from API providers
func (m *Manager) loadProxiesFromAPI() error {
	// 如果正在刷新，直接返回
	if m.isRefreshing.Load() {
		return fmt.Errorf("proxy refresh already in progress")
	}
	m.isRefreshing.Store(true)
	defer m.isRefreshing.Store(false)

	if len(m.config.Providers) == 0 {
		return fmt.Errorf("no proxy providers configured")
	}

	uniqueProxies := make(map[string]bool) // 用于追踪完整的代理地址
	var newProxies []*Proxy
	var loadErrors []error
	maxRetries := 3

	for i := range m.config.Providers {
		provider := &m.config.Providers[i]
		if !provider.Enable {
			continue
		}

		for retry := 0; retry < maxRetries; retry++ {
			// 从配置中获取参数
			params := url.Values{}
			// 获取对应类型的参数
			for key, value := range provider.GetParams() {
				if value != "" {
					params.Add(key, value)
				}
			}

			// 构建完整URL
			fullURL := provider.APIURL
			if len(params) > 0 {
				fullURL = fullURL + "?" + params.Encode()
			}

			if m.config.ValidateEnable {
				fmt.Printf("[DEBUG] 发送API请求到 %s (重试 %d): %s\n", provider.Name, retry, fullURL)
			}

			// 发送请求
			resp, err := m.client.Get(fullURL)
			if err != nil {
				if retry == maxRetries-1 {
					return fmt.Errorf("provider %s request failed after %d retries: %v", provider.Name, maxRetries, err)
				}
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			if err != nil {
				loadErrors = append(loadErrors, fmt.Errorf("provider %s read response failed: %v", provider.Name, err))
				continue
			}

			if m.config.ValidateEnable {
				fmt.Printf("[DEBUG] 从 %s 收到响应: %s\n", provider.Name, string(body))
			}

			// 尝试使用提供商特定的响应解析器
			proxies, err := m.parseProviderResponse(provider, body)
			if err != nil {
				loadErrors = append(loadErrors, fmt.Errorf("provider %s parse response failed: %v", provider.Name, err))
				continue
			}

			// 处理代理地址
			for _, proxyURL := range proxies {
				if !strings.HasPrefix(strings.ToLower(proxyURL), "http://") {
					proxyURL = "http://" + proxyURL
				}

				// 解析代理地址
				parsedURL, err := url.Parse(proxyURL)
				if err != nil {
					continue
				}

				// 如果这个代理地址已经存在，跳过
				if uniqueProxies[proxyURL] {
					continue
				}

				// 记录完整代理地址
				uniqueProxies[proxyURL] = true

				newProxies = append(newProxies, &Proxy{
					URL:      proxyURL,
					Protocol: "http",
					Host:     parsedURL.Hostname(),
					Type:     TYPE_HTTP,
					Status:   STATUS_ACTIVE,
					Country:  provider.GetCountry(),
					LastUsed: time.Now(),
				})

				if m.config.ValidateEnable {
					fmt.Printf("[DEBUG] 添加代理: %s\n", proxyURL)
				}
			}

			// 如果已经获取到足够的代理，就停止重试
			if len(uniqueProxies) >= m.minProxies {
				break
			}

			// 在重试之前等待一小段时间
			if retry < maxRetries-1 {
				time.Sleep(time.Second * 2)
			}
		}

		if m.config.ValidateEnable {
			fmt.Printf("[DEBUG] 从提供商 %s 获取到 %d 个代理\n",
				provider.Name, len(uniqueProxies))
		}
	}

	// 更新代理列表
	m.mu.Lock()
	m.proxies = newProxies
	proxyCount := len(m.proxies)
	m.mu.Unlock()

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] 最终加载了 %d 个代理\n", proxyCount)
	}

	// 如果没有获取到足够的代理，返回错误
	if proxyCount < m.minProxies {
		return fmt.Errorf("insufficient proxies: got %d, need %d", proxyCount, m.minProxies)
	}

	if len(loadErrors) > 0 {
		// Log the errors
		for _, err := range loadErrors {
			fmt.Printf("[ERROR] %v\n", err)
		}
		// Or return a combined error
		return fmt.Errorf("encountered %d errors: %v", len(loadErrors), loadErrors[0])
	}

	return nil
}

// parseProviderResponse 根据不同提供商解析响应
func (m *Manager) parseProviderResponse(provider *Provider, body []byte) ([]string, error) {
	var proxies []string

	switch provider.Type {
	case "flyproxy": // FlyProxy API格式
		var response struct {
			Code int         `json:"code"`
			Msg  string      `json:"msg"`
			Data interface{} `json:"data"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, err
		}

		// 解析msg字段中的JSON
		var msgData struct {
			Code int `json:"code"`
			Data struct {
				Addr []string `json:"addr"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(response.Msg), &msgData); err != nil {
			return nil, err
		}
		proxies = msgData.Data.Addr

	case "standard": // 标准API格式
		var response struct {
			Code int `json:"code"`
			Data struct {
				List []string `json:"list"`
			} `json:"list"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, err
		}
		proxies = response.Data.List

	default: // 默认格式，尝试多种解析方式
		// 尝试解析为数组格式
		var arrayResponse []string
		if err := json.Unmarshal(body, &arrayResponse); err == nil {
			return arrayResponse, nil
		}

		// 尝试解析为对象格式
		var objResponse map[string]interface{}
		if err := json.Unmarshal(body, &objResponse); err == nil {
			// 尝试从data字段获取代理列表
			if data, ok := objResponse["data"].(map[string]interface{}); ok {
				if list, ok := data["list"].([]interface{}); ok {
					for _, item := range list {
						if proxy, ok := item.(string); ok {
							proxies = append(proxies, proxy)
						}
					}
				}
			}
		}
	}

	return proxies, nil
}

// loadProxiesFromProvider loads proxies from a single provider
func (m *Manager) loadProxiesFromProvider(provider *Provider) error {
	client := &http.Client{
		Timeout: time.Duration(provider.GetTimeout()) * time.Millisecond,
	}

	// 构建请求URL
	apiURL := provider.APIURL
	params := provider.GetParams()

	// 构建查询字符串
	queryParams := url.Values{}
	for key, value := range params {
		queryParams.Add(key, value)
	}

	// 添加查询参数到URL
	if len(queryParams) > 0 {
		apiURL = apiURL + "?" + queryParams.Encode()
	}

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] 发送API请求: %s\n", apiURL)
	}

	// 发送请求
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] API响应: %s\n", string(body))
	}

	// 解析响应
	var response GenericAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if response.Code != 200 {
		return fmt.Errorf("API error: %s", response.Msg)
	}

	// 解析代理列表
	var proxies []*Proxy
	switch data := response.Data.(type) {
	case map[string]interface{}:
		if list, ok := data["list"].([]interface{}); ok {
			for _, item := range list {
				if proxyStr, ok := item.(string); ok {
					proxy := &Proxy{
						URL:      proxyStr,
						Type:     TYPE_HTTP,
						Status:   STATUS_ACTIVE,
						Country:  provider.GetCountry(),
						LastUsed: time.Now(),
					}
					// Ensure proxy URL has protocol scheme
					if !strings.HasPrefix(strings.ToLower(proxy.URL), "http://") && !strings.HasPrefix(strings.ToLower(proxy.URL), "https://") {
						proxy.URL = "http://" + proxy.URL
					}
					proxies = append(proxies, proxy)
				}
			}
		}
	case []interface{}:
		for _, item := range data {
			if proxyStr, ok := item.(string); ok {
				proxy := &Proxy{
					URL:      proxyStr,
					Type:     TYPE_HTTP,
					Status:   STATUS_ACTIVE,
					Country:  provider.GetCountry(),
					LastUsed: time.Now(),
				}
				// Ensure proxy URL has protocol scheme
				if !strings.HasPrefix(strings.ToLower(proxy.URL), "http://") && !strings.HasPrefix(strings.ToLower(proxy.URL), "https://") {
					proxy.URL = "http://" + proxy.URL
				}
				proxies = append(proxies, proxy)
			}
		}
	}

	if len(proxies) == 0 {
		return fmt.Errorf("no valid proxies found in response")
	}

	// Shuffle the proxies from this provider before adding them
	m.shuffleProxies(proxies)

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] Added and shuffled %d proxies from provider %s\n", len(proxies), provider.Name)
	}

	m.proxies = append(m.proxies, proxies...)
	return nil
}

// AddProxyPool adds a new proxy pool to the manager
func (m *Manager) AddProxyPool(pool *ProxyPool) error {
	if pool == nil {
		return fmt.Errorf("proxy pool cannot be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pools = append(m.pools, pool)
	if m.config.ValidateEnable {
		fmt.Printf("Proxy pool added: %s\n", pool.Name)
	}
	return nil
}

// shuffleProxies shuffles the given proxy slice using the manager's RNG
func (m *Manager) shuffleProxies(proxies []*Proxy) {
	m.rng.Shuffle(len(proxies), func(i, j int) {
		proxies[i], proxies[j] = proxies[j], proxies[i]
	})
}

// maintainAPIProxyPool maintains the API proxy pool with a single worker
func (m *Manager) maintainAPIProxyPool() {
	ticker := time.NewTicker(m.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.refreshAPIProxiesIfNeeded()
		case <-m.refreshChan:
			m.refreshAPIProxiesIfNeeded()
		}
	}
}

// refreshAPIProxiesIfNeeded refreshes the API proxy list if needed
func (m *Manager) refreshAPIProxiesIfNeeded() {
	// 如果正在刷新，直接返回
	if m.isRefreshing.Load() {
		return
	}

	m.mu.RLock()
	proxyCount := len(m.proxies)
	m.mu.RUnlock()

	lastRefresh := m.lastRefreshTime.Load().(time.Time)

	// 根据配置的刷新间隔来刷新代理列表
	if time.Since(lastRefresh) >= m.refreshInterval {
		if m.isRefreshing.CompareAndSwap(false, true) {
			defer m.isRefreshing.Store(false)

			if m.config.ValidateEnable {
				fmt.Printf("[DEBUG] 开始刷新代理列表 (当前代理数: %d, 最后刷新时间: %v)\n",
					proxyCount, lastRefresh)
			}

			if err := m.loadProxiesFromAPI(); err != nil {
				fmt.Printf("[ERROR] Failed to refresh proxies: %v\n", err)
				return
			}

			// 更新最后刷新时间
			m.lastRefreshTime.Store(time.Now())
		}
	}
}

// GetNextProxy returns the next available proxy from the pool
// 只用于API和FILE模式
func (m *Manager) GetNextProxy() (*Proxy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// SERVER模式不应该使用此方法
	if m.config.Type == TYPE_SERVER {
		return nil, fmt.Errorf("GetNextProxy is not supported for SERVER mode, use GetClient or GetWebSocketDialer instead")
	}

	if len(m.proxies) == 0 {
		select {
		case m.refreshChan <- struct{}{}:
		default:
		}
		return nil, fmt.Errorf("no proxies available")
	}

	// 对于API和FILE模式，使用轮询方式选择代理
	if m.lastProxyIndex >= len(m.proxies) {
		m.lastProxyIndex = 0
	}

	selectedProxy := m.proxies[m.lastProxyIndex]
	m.lastProxyIndex = (m.lastProxyIndex + 1) % len(m.proxies)

	// 记录这个代理的使用时间
	now := time.Now()
	m.usedProxies.Store(selectedProxy.URL, now)

	// 处理代理URL中的随机占位符
	if strings.Contains(selectedProxy.URL, "%") {
		// 导入goto-http/pkg/random包来处理随机变量替换
		g := random.NewGenerator()

		// 替换随机字符串
		if strings.Contains(selectedProxy.URL, "%RANDSTR%") {
			str, _ := g.String(8, "all")
			selectedProxy.URL = strings.ReplaceAll(selectedProxy.URL, "%RANDSTR%", str)
		}

		// 替换随机整数
		if strings.Contains(selectedProxy.URL, "%RANDINT%") {
			num, _ := g.IntRange(1000, 9999)
			selectedProxy.URL = strings.ReplaceAll(selectedProxy.URL, "%RANDINT%", fmt.Sprintf("%d", num))
		}

		// 替换UUID
		if strings.Contains(selectedProxy.URL, "%TOKEN%") {
			token, _ := g.UUID()
			selectedProxy.URL = strings.ReplaceAll(selectedProxy.URL, "%TOKEN%", token)
		}
	}

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] 选择并使用代理: %s (可用: %d)\n",
			selectedProxy.URL, len(m.proxies))
	}
	return selectedProxy, nil
}

// cleanupUsedProxies 清理过期的已用代理记录
func (m *Manager) cleanupUsedProxies() {
	ticker := time.NewTicker(m.proxyTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			m.usedProxies.Range(func(key, value interface{}) bool {
				if lastUsed, ok := value.(time.Time); ok {
					if now.Sub(lastUsed) >= m.proxyTimeout {
						m.usedProxies.Delete(key)
						if m.config.ValidateEnable {
							fmt.Printf("[DEBUG] Cleaned up expired proxy: %s\n", key)
						}
					}
				}
				return true
			})
		}
	}
}

// GetClient returns a new HTTP client configured with a proxy
func (m *Manager) GetClient() (*httplib.Client, error) {
	options := httplib.ClientOptions{
		Timeout:         30 * time.Second,
		KeepAlive:       true,
		NoCompression:   true,
		Debug:           m.debugEnabled,
		MaxConns:        m.config.MaxConns,        // 使用config中的配置
		MaxConnsPerHost: m.config.MaxConnsPerHost, // 使用config中的配置
		RetryTimes:      3,
		RetryDelay:      time.Second * 2,
		SkipVerify:      true,
	}

	// 如果未设置，使用默认值
	if options.MaxConns == 0 {
		options.MaxConns = 100
	}
	if options.MaxConnsPerHost == 0 {
		options.MaxConnsPerHost = 100
	}

	client, err := httplib.NewClient(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	// 检查是否为GUI模式
	isGUI := os.Getenv("NO_LOGGING") == "true"

	// 根据代理类型设置不同的代理获取方式
	if m.config.Type == TYPE_SERVER {
		// SERVER模式使用专用的获取代理方法，每次都生成新的带随机session的代理
		client.SetProxyFunc(func() (*url.URL, error) {
			proxy, err := m.getServerProxy()
			if err != nil {
				return nil, fmt.Errorf("failed to get server proxy: %v", err)
			}
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy URL: %v", err)
			}
			if m.config.ValidateEnable {
				fmt.Printf("[DEBUG] 选择并使用代理: %s\n", proxy.URL)
			}
			return proxyURL, nil
		})

		// 如果是GUI模式，设置自定义传输以过滤错误日志
		if isGUI {
			// 获取原始传输
			origTransport := client.Client.Transport.(*http.Transport)

			// 创建自定义传输
			customTransport := &http.Transport{
				Proxy:                 origTransport.Proxy,
				TLSClientConfig:       origTransport.TLSClientConfig,
				MaxIdleConns:          origTransport.MaxIdleConns,
				IdleConnTimeout:       origTransport.IdleConnTimeout,
				TLSHandshakeTimeout:   origTransport.TLSHandshakeTimeout,
				ExpectContinueTimeout: origTransport.ExpectContinueTimeout,
				DisableKeepAlives:     origTransport.DisableKeepAlives,
				// 使用自定义拨号器避免错误日志
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// 使用不记录错误的拨号器
					dialer := &net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					conn, err := dialer.DialContext(ctx, network, addr)

					// 屏蔽特定错误的输出
					if err != nil {
						if strings.Contains(err.Error(), "connection refused") ||
							strings.Contains(err.Error(), "no such host") ||
							strings.Contains(err.Error(), "i/o timeout") {
							return nil, fmt.Errorf("request failed after 3 retries: proxyconnect tcp: dial tcp %s: %v", addr, err)
						}
					}

					return conn, err
				},
			}

			// 设置自定义传输
			client.SetCustomTransport(customTransport)
		}
	} else if m.config.Type != TYPE_NONE {
		// API和FILE模式使用GetNextProxy方法
		client.SetProxyFunc(func() (*url.URL, error) {
			proxy, err := m.GetNextProxy()
			if err != nil {
				return nil, fmt.Errorf("failed to get proxy: %v", err)
			}
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy URL: %v", err)
			}
			return proxyURL, nil
		})

		// 如果是GUI模式，设置自定义传输以过滤错误日志
		if isGUI {
			// 获取原始传输
			origTransport := client.Client.Transport.(*http.Transport)

			// 创建自定义传输
			customTransport := &http.Transport{
				Proxy:                 origTransport.Proxy,
				TLSClientConfig:       origTransport.TLSClientConfig,
				MaxIdleConns:          origTransport.MaxIdleConns,
				IdleConnTimeout:       origTransport.IdleConnTimeout,
				TLSHandshakeTimeout:   origTransport.TLSHandshakeTimeout,
				ExpectContinueTimeout: origTransport.ExpectContinueTimeout,
				DisableKeepAlives:     origTransport.DisableKeepAlives,
				// 使用自定义拨号器避免错误日志
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// 使用不记录错误的拨号器
					dialer := &net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					conn, err := dialer.DialContext(ctx, network, addr)

					// 屏蔽特定错误的输出
					if err != nil {
						if strings.Contains(err.Error(), "connection refused") ||
							strings.Contains(err.Error(), "no such host") ||
							strings.Contains(err.Error(), "i/o timeout") {
							return nil, fmt.Errorf("request failed after 3 retries: proxyconnect tcp: dial tcp %s: %v", addr, err)
						}
					}

					return conn, err
				},
			}

			// 设置自定义传输
			client.SetCustomTransport(customTransport)
		}
	}

	return client, nil
}

// GetWebSocketDialer returns a new WebSocket dialer configured with a proxy
func (m *Manager) GetWebSocketDialer() (*websocket.Dialer, error) {
	var proxy *Proxy
	var err error

	// 根据代理类型选择不同的代理获取方式
	if m.config.Type == TYPE_SERVER {
		// SERVER模式使用专用的获取代理方法
		proxy, err = m.getServerProxy()
	} else {
		// API和FILE模式使用GetNextProxy方法
		proxy, err = m.GetNextProxy()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get proxy: %v", err)
	}

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] WebSocket使用代理: %s\n", proxy.URL)
	}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 30 * time.Second,
	}

	return dialer, nil
}

// proxyTransport wraps http.Transport to add request tracking
type proxyTransport struct {
	*http.Transport
	proxyURL string
	debug    bool
	attempt  int
}

func (pt *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
		fmt.Printf("  代理服务器: %s\n", pt.proxyURL)
		fmt.Printf("  重试次数: %d/3\n", pt.attempt)

		fmt.Printf("\n[DEBUG] 请求头:\n")
		for key, values := range req.Header {
			fmt.Printf("  %s: %v\n", key, values)
		}
		fmt.Printf("\n[DEBUG] ====================================================\n")
	}

	start := time.Now()
	resp, err := pt.Transport.RoundTrip(req)
	duration := time.Since(start)

	if pt.debug {
		fmt.Printf("\n[DEBUG] ===================== 响应详情 =====================\n")
		if err != nil {
			fmt.Printf("[DEBUG] 请求失败:\n")
			fmt.Printf("  目标URL: %s\n", req.URL.String())
			fmt.Printf("  使用代理: %s\n", pt.proxyURL)
			fmt.Printf("  错误信息: %v\n", err)
			fmt.Printf("  请求耗时: %v\n", duration)
		} else {
			fmt.Printf("[DEBUG] 请求成功:\n")
			fmt.Printf("  目标URL: %s\n", req.URL.String())
			fmt.Printf("  使用代理: %s\n", pt.proxyURL)
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

// Close gracefully shuts down the proxy manager and releases resources
func (m *Manager) Close() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxies = nil
	m.pools = nil
}

// loadProxiesFromServer loads proxies from server providers
func (m *Manager) loadProxiesFromServer() error {
	if len(m.config.Providers) == 0 {
		return fmt.Errorf("no server providers configured")
	}

	// 存储启用的服务器代理提供者
	var enabledProviders []Provider

	for i := range m.config.Providers {
		provider := &m.config.Providers[i]
		if !provider.Enable {
			continue
		}

		if m.config.ValidateEnable {
			fmt.Printf("[DEBUG] 处理服务器提供者: %s\n", provider.Name)
		}

		// 保存启用的提供者
		enabledProviders = append(enabledProviders, *provider)
	}

	if len(enabledProviders) == 0 {
		return fmt.Errorf("no enabled server providers found")
	}

	// 更新服务器提供者列表
	m.mu.Lock()
	m.serverProviders = enabledProviders

	// 为SERVER模式添加一个占位代理到proxies列表中
	// 这不会被实际使用，但可以确保代码的其他部分能够正常工作
	// 例如，一些地方可能会检查proxies列表长度
	if len(m.proxies) == 0 {
		// 创建一个代理实例作为占位符
		provider := enabledProviders[0]
		placeholderURL := fmt.Sprintf("http://%s_placeholder:placeholder@%s",
			provider.Params.Username, provider.APIURL)

		m.proxies = []*Proxy{
			{
				URL:      placeholderURL,
				Protocol: "http",
				Host:     strings.TrimPrefix(provider.APIURL, "http://"),
				Type:     TYPE_HTTP,
				Status:   STATUS_ACTIVE,
				Country:  provider.GetCountry(),
				LastUsed: time.Now(),
			},
		}

		if m.config.ValidateEnable {
			fmt.Printf("[DEBUG] 添加了1个占位代理 (这不会被实际使用)\n")
		}
	}
	m.mu.Unlock()

	if m.config.ValidateEnable {
		fmt.Printf("[DEBUG] 加载了 %d 个服务器代理提供者\n", len(enabledProviders))
	}

	return nil
}

// getServerProxy 从服务器代理提供者中生成一个带有随机session的代理URL
func (m *Manager) getServerProxy() (*Proxy, error) {
	m.mu.RLock()
	if len(m.serverProviders) == 0 {
		m.mu.RUnlock()
		return nil, fmt.Errorf("no server providers available")
	}

	// 随机选择一个提供者
	provider := m.serverProviders[m.rng.Intn(len(m.serverProviders))]
	m.mu.RUnlock()

	// 从服务器配置中获取参数
	username := provider.Params.Username
	password := provider.Params.Password
	life := provider.Params.Life

	// 生成随机会话ID
	sessionLen := 6 + m.rng.Intn(7) // 6到12之间的随机长度
	session := generateRandomString(sessionLen)

	// 构建服务器地址
	serverAddress := provider.APIURL
	if !strings.Contains(serverAddress, "://") {
		serverAddress = "http://" + serverAddress
	}

	// 解析服务器URL以获取主机名和端口
	serverURL, err := url.Parse(serverAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL %s: %v", serverAddress, err)
	}

	// 获取服务器主机和端口
	host := serverURL.Hostname()
	port := serverURL.Port()
	if port == "" {
		if serverURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// 构建代理连接字符串
	// 格式: http://username_session-random_life-30:password@ip:port
	authPart := ""
	if username != "" {
		authPart = username
		if session != "" {
			authPart += "_session-" + session
		}
		if life > 0 {
			authPart += fmt.Sprintf("_life-%d", life)
		}
		if password != "" {
			authPart += ":" + password
		}
		authPart += "@"
	}

	proxyURL := fmt.Sprintf("http://%s%s:%s", authPart, host, port)

	return &Proxy{
		URL:      proxyURL,
		Protocol: "http",
		Host:     host,
		Type:     TYPE_HTTP,
		Status:   STATUS_ACTIVE,
		Country:  provider.GetCountry(),
		LastUsed: time.Now(),
	}, nil
}

// generateRandomString 生成指定长度的随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
