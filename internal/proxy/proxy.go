package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	LogProxy *log.Logger
	LogError *log.Logger
)

func init() {
	LogProxy = log.New(os.Stdout, "PROXY: ", log.Ldate|log.Ltime|log.Lshortfile)
	LogError = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// APIResponse API响应结构
type APIResponse struct {
	Code      int         `json:"code"`
	Msg       string      `json:"msg"`
	Data      interface{} `json:"data"`
	RequestID string      `json:"request_id"`
}

func init() {
	// 初始化随机数生成器
	rand.Seed(time.Now().UnixNano())
}

// checkCountrySupport 检查是否支持国家参数
func checkCountrySupport(provider *Provider, country string, _ bool) error {
	if !provider.SupportCountrys && country != "" {
		if provider.Type == PROVIDER_TYPE_API {
			// API模式下，如果是all模式或单独使用，都自动忽略不支持的国家参数
			log.Printf("Warning: Provider %s does not support country selection, ignoring country parameter", provider.Name)
			return nil
		}
		// 服务器模式下，如果不支持国家选择则返回错误
		return fmt.Errorf("provider %s does not support country selection", provider.Name)
	}
	return nil
}

// LoadProxiesFromAPI 从API加载代理列表
func LoadProxiesFromAPI(provider *Provider, isAllMode bool) ([]string, error) {
	LogProxy.Printf("Loading proxies from API provider: %s", provider.Name)

	// 如果是代理服务器分发模式，直接返回代理服务器地址
	if provider.Type == PROVIDER_TYPE_SERVER {
		proxyURL := provider.APIURL
		// 确保URL包含协议
		if !strings.HasPrefix(proxyURL, "http://") && !strings.HasPrefix(proxyURL, "https://") {
			proxyURL = "http://" + proxyURL
		}

		// 解析URL以获取主机和端口
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
		}

		// 构建基本的代理URL（保留端口号）
		host := parsedURL.Host // Host 包含主机名和端口号
		path := parsedURL.Path
		if path == "" {
			path = "/"
		}

		// 添加认证信息
		if provider.Params.Username != "" && provider.Params.Password != "" {
			proxyURL = fmt.Sprintf("http://%s:%s@%s%s",
				provider.Params.Username,
				provider.Params.Password,
				host,
				path)
		} else {
			proxyURL = fmt.Sprintf("http://%s%s", host, path)
		}

		// 获取随机国家代码并检查是否支持国家选择
		if country := provider.GetRandomCountry(); country != "" {
			if err := checkCountrySupport(provider, country, isAllMode); err != nil {
				return nil, err
			}

			if provider.SupportCountrys {
				// 解析URL并添加国家参数
				parsedURL, err := url.Parse(proxyURL)
				if err != nil {
					return nil, fmt.Errorf("failed to parse proxy URL: %v", err)
				}
				query := parsedURL.Query()
				query.Set("area", country)
				parsedURL.RawQuery = query.Encode()
				proxyURL = parsedURL.String()
			}
		}

		LogProxy.Printf("Using server mode proxy: %s", proxyURL)
		return []string{proxyURL}, nil
	}

	// API模式的处理逻辑
	reqURL := provider.APIURL
	params := url.Values{}

	// 添加API参数
	if provider.Params.AppKey != "" {
		params.Add("app_key", provider.Params.AppKey)
	}
	if provider.Params.Num > 0 {
		params.Add("num", strconv.Itoa(provider.Params.Num))
	}

	// 处理协议参数 (1: http, 2: socks5)
	switch provider.Params.Protocol {
	case 1:
		params.Add("protocol", "http")
	case 2:
		params.Add("protocol", "socks5")
	default:
		params.Add("protocol", "http") // 默认使用http
	}

	if provider.Params.Format != "" {
		params.Add("format", provider.Params.Format)
	}
	if provider.Params.UPID != "" {
		params.Add("upid", provider.Params.UPID)
	}
	if provider.Params.PT > 0 {
		params.Add("pt", strconv.Itoa(provider.Params.PT))
	}
	if provider.Params.Life > 0 {
		params.Add("life", strconv.Itoa(provider.Params.Life))
	}

	// 如果不是all模式，并且指定了国家，则添加国家参数
	if !isAllMode && len(provider.Countries) > 0 {
		// 随机选择一个国家
		country := provider.Countries[rand.Intn(len(provider.Countries))]
		params.Add("country", country)
		LogProxy.Printf("Selected country: %s", country)
	}

	// 添加查询参数到URL
	if len(params) > 0 {
		reqURL = reqURL + "?" + params.Encode()
	}

	LogProxy.Printf("Requesting proxies from URL: %s", reqURL)

	// 发送请求
	resp, err := http.Get(reqURL)
	if err != nil {
		LogError.Printf("Failed to fetch proxies from API: %v", err)
		return nil, fmt.Errorf("failed to fetch proxies from API: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		LogError.Printf("Failed to read API response: %v", err)
		return nil, fmt.Errorf("failed to read API response: %v", err)
	}

	LogProxy.Printf("API response: %s", string(body))

	// 解析JSON响应
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"msg"`
		Data    struct {
			List []string `json:"list"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		LogError.Printf("Failed to parse API response: %v", err)
		return nil, fmt.Errorf("failed to parse API response: %v", err)
	}

	// 检查响应状态码
	if response.Code != 200 {
		LogError.Printf("API error: %s", response.Message)
		return nil, fmt.Errorf("API error: %s", response.Message)
	}

	if len(response.Data.List) == 0 {
		LogError.Printf("No proxies returned from API")
		return nil, fmt.Errorf("no proxies returned from API")
	}

	LogProxy.Printf("Successfully loaded %d proxies from API", len(response.Data.List))
	return response.Data.List, nil
}

// CheckProxy 检查代理是否有效
func CheckProxy(proxyURL string) error {
	if os.Getenv("NO_LOGGING") == "true" {
		// 在无日志模式下静默执行检查，不输出任何日志
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(_ *http.Request) (*url.URL, error) {
					return url.Parse(proxyURL)
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get("https://httpbin.org/ip")
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("proxy check failed: status code %d", resp.StatusCode)
		}
		return nil
	}

	LogProxy.Printf("Checking proxy: %s", proxyURL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		LogError.Printf("Proxy check failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		LogError.Printf("Proxy check failed: status code %d", resp.StatusCode)
		return fmt.Errorf("proxy check failed: status code %d", resp.StatusCode)
	}

	LogProxy.Printf("Proxy check passed: %s", proxyURL)
	return nil
}

// ErrNoValidProxies 表示没有可用的代理
var ErrNoValidProxies = fmt.Errorf("no valid proxies available")

// ValidateProxies 验证代理列表
func ValidateProxies(proxies []string, provider *Provider) ([]string, error) {
	if provider != nil && provider.Type == PROVIDER_TYPE_SERVER {
		LogProxy.Printf("Provider is in server mode, skipping proxy validation")
		return proxies, nil
	}

	LogProxy.Printf("Validating %d proxies...", len(proxies))
	var validProxies []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 创建工作池
	workers := 5
	if len(proxies) < workers {
		workers = len(proxies)
	}

	// 创建任务通道
	tasks := make(chan string, len(proxies))
	for _, proxy := range proxies {
		tasks <- proxy
	}
	close(tasks)

	// 启动工作协程
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxy := range tasks {
				if isValidProxy(proxy) {
					mu.Lock()
					validProxies = append(validProxies, proxy)
					mu.Unlock()
					LogProxy.Printf("Valid proxy found: %s", proxy)
				} else {
					LogProxy.Printf("Invalid proxy: %s", proxy)
				}
			}
		}()
	}

	wg.Wait()

	if len(validProxies) == 0 {
		LogError.Printf("No valid proxies found")
		return nil, ErrNoValidProxies
	}

	LogProxy.Printf("Found %d valid proxies", len(validProxies))
	return validProxies, nil
}

// LoadProxiesFromFile 从文件加载代理列表
func LoadProxiesFromFile(filename string) ([]string, error) {
	LogProxy.Printf("Loading proxies from file: %s", filename)

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open proxy file: %v", err)
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Ensure proxy URL has protocol scheme
		if !strings.HasPrefix(strings.ToLower(line), "http://") && !strings.HasPrefix(strings.ToLower(line), "https://") {
			line = "http://" + line
		}
		proxies = append(proxies, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading proxy file: %v", err)
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found in file")
	}

	LogProxy.Printf("Loaded %d proxies from file", len(proxies))
	return proxies, nil
}

// LoadAPIConfigFromFile 从文件加载API配置
func LoadAPIConfigFromFile(filename string) (*APIConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config APIConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// isValidProxy 检查代理是否有效
func isValidProxy(proxy string) bool {
	// 创建测试客户端
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	// 测试连接
	resp, err := client.Get("http://www.google.com")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
