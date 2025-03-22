package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"goto-http/internal/attack"
	"goto-http/internal/logger"
	"goto-http/internal/proxy"
	"goto-http/internal/termui"
	"goto-http/internal/useragent"
	"goto-http/pkg/random"
)

var (
	version = "1.0.0"
	banner  = `
   ______      __          __  __ _______ _______ ____  
  / ____/___  / /_____    / / / //_  __// /_/ _ \/ __ \ 
 / / __/ __ \/ __/ __ \  / /_/ /  / /  / __/  __/ /_/ /
/ /_/ / /_/ / /_/ /_/ / / __  /  / /  / /_/ ___/ ____/ 
\____/\____/\__/\____/ /_/ /_/  /_/   \__/_/  /_/      v%s

Goto-HTTP - 高性能HTTP压力测试工具
`

	// 日志记录器
	errorLogger  *log.Logger
	targetLogger *log.Logger
	proxyLogger  *log.Logger

	// 日志文件
	errorLogFile  *os.File
	proxyLogFile  *os.File
	targetLogFile *os.File

	// 全局dashboard实例
	globalDashboard *termui.Dashboard

	// 命令行参数
	rootCmd = &cobra.Command{
		Use:     "goto-http",
		Short:   "Goto-HTTP - 高性能HTTP压力测试工具",
		Version: version,
		RunE:    runCommand,
	}

	// 命令行参数
	bypass string

	// GUI参数
	guiMode bool

	// 攻击参数
	target   string
	method   string
	duration int
	rate     int
	workers  int
	timeout  int
	mode     string
	interval int

	// 代理参数
	proxyType     string
	proxyFile     string
	proxyPool     string
	proxyTimeout  int
	proxyCountrys string

	// User-Agent参数
	uaType   string
	uaCustom string

	// HTTP参数
	http2          bool
	keepAlive      bool
	followRedirect bool

	// WebSocket参数
	wsFrameSize   int
	wsCompression bool

	// 其他参数
	debug    bool
	logLevel string

	// 新的参数
	headers  string
	cookies  string
	postData string
	referer  string
)

// ProxyConfig 代理配置结构
type ProxyConfig struct {
	Version string `yaml:"version"`
	File    struct {
		Nodes []struct {
			Name   string `yaml:"name"`
			Enable bool   `yaml:"enable"`
			Type   string `yaml:"type"`
			Path   string `yaml:"path"`
		} `yaml:"nodes"`
	} `yaml:"file"`
	Server struct {
		Enable bool   `yaml:"enable"`
		Type   string `yaml:"type"`
		Nodes  []struct {
			Name            string   `yaml:"name"`
			Enable          bool     `yaml:"enable"`
			Type            string   `yaml:"type"`
			APIURL          string   `yaml:"api_url"`
			SupportCountrys bool     `yaml:"support_countrys"`
			Countries       []string `yaml:"countries"`
			Params          struct {
				Username string `yaml:"username"`
				Password string `yaml:"password"`
				Session  string `yaml:"session"`
				Protocol int    `yaml:"protocol"`
				Life     int    `yaml:"life"`
				Area     string `yaml:"area"`
			} `yaml:"params"`
		} `yaml:"nodes"`
	} `yaml:"server"`
	API struct {
		Enable bool   `yaml:"enable"`
		Type   string `yaml:"type"`
		Nodes  []struct {
			Name            string   `yaml:"name"`
			Enable          bool     `yaml:"enable"`
			Type            string   `yaml:"type"`
			APIURL          string   `yaml:"api_url"`
			SupportCountrys bool     `yaml:"support_countrys"`
			Countries       []string `yaml:"countries"`
			Params          struct {
				AppKey   string `yaml:"app_key"`
				Num      int    `yaml:"num"`
				Protocol int    `yaml:"protocol"`
				UPID     string `yaml:"upid"`
				PT       int    `yaml:"pt"`
				Format   string `yaml:"format"`
				Life     int    `yaml:"life"`
				Name     string `yaml:"name"`
				Time     int    `yaml:"time"`
			} `yaml:"params"`
			Response struct {
				Format      string `yaml:"format"`
				SuccessCode int    `yaml:"success_code"`
				JSONPath    struct {
					Code      string `yaml:"code"`
					Message   string `yaml:"message"`
					Data      string `yaml:"data"`
					ProxyList string `yaml:"proxy_list"`
				} `yaml:"json_path"`
			} `yaml:"response"`
		} `yaml:"nodes"`
	} `yaml:"api"`
}

// 读取代理配置文件
func loadProxyConfig() (*ProxyConfig, error) {
	data, err := os.ReadFile("configs/config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy config: %v", err)
	}

	var config ProxyConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse proxy config: %v", err)
	}

	return &config, nil
}

// convertToProxyOptions converts the new config format to proxy.Config
func convertToProxyOptions(proxyConfig *ProxyConfig, proxyType string, nodeName string) (*proxy.Config, error) {
	var pType proxy.ProxyType
	switch proxyType {
	case "none":
		pType = proxy.TYPE_NONE
	case "file":
		pType = proxy.TYPE_FILE
	case "api":
		pType = proxy.TYPE_API
	case "server":
		pType = proxy.TYPE_SERVER
	default:
		return nil, fmt.Errorf("invalid proxy type: %s", proxyType)
	}

	config := &proxy.Config{
		Type:           pType,
		MaxFails:       5,
		RetryInterval:  100,
		Timeout:        10,
		Retries:        3,
		CheckInterval:  10,
		MaxFailures:    5,
		ValidateEnable: true,
		ValidateURL:    "https://httpbin.org/ip",
	}

	if proxyType == "none" {
		return config, nil
	}

	// Handle file proxy type
	if proxyType == "file" {
		var availableNodes []string
		var providers []proxy.Provider
		for _, node := range proxyConfig.File.Nodes {
			if node.Enable {
				availableNodes = append(availableNodes, node.Name)
				if nodeName == "all" || nodeName == node.Name {
					config.File = node.Path
					providers = append(providers, proxy.Provider{
						Name:   node.Name,
						Type:   proxy.PROVIDER_TYPE_API,
						Enable: true,
					})
					if nodeName != "all" {
						config.Providers = providers
						return config, nil
					}
				}
			}
		}
		if len(availableNodes) == 0 {
			return nil, fmt.Errorf("no enabled file nodes found")
		}
		if nodeName != "all" {
			return nil, fmt.Errorf("node '%s' not found. Available nodes: %v", nodeName, availableNodes)
		}
		config.Providers = providers
		return config, nil
	}

	return config, nil
}

// 处理字符串中的随机占位符
func processPlaceholders(input string) string {
	if !strings.Contains(input, "%") {
		return input
	}

	// 创建随机生成器
	g := random.NewGenerator()

	// 处理%RANDSTR%，默认长度8
	if strings.Contains(input, "%RANDSTR%") {
		str, _ := g.String(8, "all")
		input = strings.ReplaceAll(input, "%RANDSTR%", str)
	}

	// 处理%RANDSTR1%到%RANDSTR9%，长度为相应数字
	for i := 1; i <= 9; i++ {
		placeholder := fmt.Sprintf("%%RANDSTR%d%%", i)
		if strings.Contains(input, placeholder) {
			str, _ := g.String(i, "all")
			input = strings.ReplaceAll(input, placeholder, str)
		}
	}

	// 处理%RANDINT%，默认范围1000-9999
	if strings.Contains(input, "%RANDINT%") {
		num, _ := g.IntRange(1000, 9999)
		input = strings.ReplaceAll(input, "%RANDINT%", fmt.Sprintf("%d", num))
	}

	// 处理%RANDINT1%到%RANDINT9%，生成1到指定位数的随机数
	for i := 1; i <= 9; i++ {
		placeholder := fmt.Sprintf("%%RANDINT%d%%", i)
		if strings.Contains(input, placeholder) {
			maxNum := int64(math.Pow10(i)) - 1
			minNum := int64(math.Pow10(i - 1))
			if i == 1 {
				minNum = 0
			}
			num, _ := g.IntRange(minNum, maxNum)
			input = strings.ReplaceAll(input, placeholder, fmt.Sprintf("%d", num))
		}
	}

	// 处理%TOKEN%，生成UUID类似的令牌
	if strings.Contains(input, "%TOKEN%") {
		token, _ := g.UUID()
		input = strings.ReplaceAll(input, "%TOKEN%", token)
	}

	return input
}

func init() {
	// 基本参数
	rootCmd.Flags().StringVarP(&target, "url", "u", "", "目标URL (必需)")
	rootCmd.Flags().StringVarP(&method, "method", "X", "GET", "HTTP方法")
	rootCmd.Flags().IntVarP(&duration, "duration", "d", 60, "攻击持续时间(秒)")
	rootCmd.Flags().IntVarP(&rate, "rate", "r", 50, "每秒请求数")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 10, "并发连接数")
	rootCmd.Flags().StringVarP(&mode, "mode", "m", "", "攻击模式")
	rootCmd.Flags().IntVarP(&interval, "interval", "i", 1000, "请求间隔(毫秒)")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "启用调试模式")

	// 代理参数
	rootCmd.Flags().StringVarP(&proxyType, "proxy-type", "P", "none", "代理类型 (none/file/api/server)")
	rootCmd.Flags().StringVar(&proxyPool, "nodes", "all", "代理节点名称，支持all或单个节点名称")
	rootCmd.Flags().IntVar(&proxyTimeout, "proxy-timeout", 10, "代理超时时间(秒)")
	rootCmd.Flags().StringVar(&proxyCountrys, "proxy-countrys", "", "代理国家/地区过滤")

	// User-Agent参数
	rootCmd.Flags().StringVarP(&uaType, "ua-type", "U", "random", "User-Agent类型")
	rootCmd.Flags().StringVarP(&uaCustom, "ua-custom", "C", "", "自定义UA文件路径")

	// HTTP参数
	rootCmd.Flags().BoolVar(&http2, "http2", false, "启用HTTP/2")
	rootCmd.Flags().BoolVar(&followRedirect, "follow-redirect", false, "跟随重定向")
	rootCmd.Flags().BoolVar(&keepAlive, "keepalive", false, "启用长连接")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "T", 30, "请求超时时间(秒)")

	// WebSocket参数
	rootCmd.Flags().IntVar(&wsFrameSize, "ws-frame-size", 1024, "WebSocket帧大小(字节)")
	rootCmd.Flags().BoolVar(&wsCompression, "ws-compression", false, "启用WebSocket压缩")

	// 请求参数
	rootCmd.Flags().StringVar(&headers, "headers", "", "自定义请求头")
	rootCmd.Flags().StringVar(&cookies, "cookies", "", "自定义Cookie")
	rootCmd.Flags().StringVar(&postData, "post-data", "", "POST数据")
	rootCmd.Flags().StringVar(&referer, "referer", "", "Referer头")

	// GUI参数
	rootCmd.Flags().BoolVar(&guiMode, "gui", false, "启用终端UI模式")

	// 命令行参数
	rootCmd.Flags().StringVar(&bypass, "bypass", "", "绕过方法")

	// 设置必需的参数
	rootCmd.MarkFlagRequired("url")
}

func runCommand(cmd *cobra.Command, args []string) error {
	// 创建上下文 - 移到最前面
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	// 创建日志目录
	if err := os.MkdirAll("logs", 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	// 初始化日志目录
	var targetLogWriter io.Writer
	var errorLogWriter io.Writer
	var proxyLogWriter io.Writer

	// 初始化日志文件
	targetLogFile, fileErr := os.OpenFile("logs/target.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if fileErr != nil {
		return fmt.Errorf("failed to open target log file: %v", fileErr)
	}
	defer targetLogFile.Close()

	errorLogFile, fileErr := os.OpenFile("logs/error.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if fileErr != nil {
		return fmt.Errorf("failed to open error log file: %v", fileErr)
	}
	defer errorLogFile.Close()

	proxyLogFile, fileErr := os.OpenFile("logs/proxy.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if fileErr != nil {
		return fmt.Errorf("failed to open proxy log file: %v", fileErr)
	}
	defer proxyLogFile.Close()

	if guiMode {
		// GUI模式：所有日志写入文件
		targetLogWriter = targetLogFile
		errorLogWriter = errorLogFile
		proxyLogWriter = proxyLogFile

		// 重定向标准输出和标准错误
		os.Stdout = targetLogFile
		os.Stderr = errorLogFile
	} else {
		// 非GUI模式：使用标准输出
		targetLogWriter = io.MultiWriter(os.Stdout, targetLogFile)
		errorLogWriter = io.MultiWriter(os.Stderr, errorLogFile)
		proxyLogWriter = io.MultiWriter(os.Stdout, proxyLogFile)
	}

	// 初始化日志记录器
	targetLogger = log.New(targetLogWriter, "[TARGET] ", log.Ldate|log.Ltime|log.Lmicroseconds)
	errorLogger = log.New(errorLogWriter, "[ERROR] ", log.Ldate|log.Ltime|log.Lmicroseconds)
	proxyLogger = log.New(proxyLogWriter, "[PROXY] ", log.Ldate|log.Ltime|log.Lmicroseconds)

	// 初始化应用日志配置
	logConfig := &logger.Config{
		Level:          logLevel,
		DisableConsole: guiMode,
		File:           "logs/app.log",
	}

	if logErr := logger.InitLogger(logConfig); logErr != nil {
		return fmt.Errorf("failed to initialize logger: %v", logErr)
	}

	// 初始化代理管理器和相关设置
	var proxyOptions *proxy.Config

	if proxyType != "none" {
		if debug {
			targetLogger.Printf("Loading proxy configuration...")
		}

		proxyConfig, err := loadProxyConfig()
		if err != nil {
			errorLogger.Printf("Failed to load proxy config: %v", err)
			return fmt.Errorf("failed to load proxy config: %v", err)
		}

		proxyOptions, err = convertToProxyOptions(proxyConfig, proxyType, proxyPool)
		if err != nil {
			errorLogger.Printf("Failed to convert proxy config: %v", err)
			return fmt.Errorf("failed to convert proxy config: %v", err)
		}

		// 初始化代理管理器来验证配置
		_, err = proxy.NewManager(proxyOptions)
		if err != nil {
			errorLogger.Printf("Failed to initialize proxy manager: %v", err)
			// 即使出错，我们也继续执行，但会将proxyType设置为none
			targetLogger.Printf("WARNING: Falling back to no proxy mode due to initialization error")
			proxyType = "none"
			proxyOptions = &proxy.Config{
				Type: proxy.ProxyType("none"),
			}
		} else if debug {
			targetLogger.Printf("Proxy configuration loaded successfully")
			targetLogger.Printf("Proxy type: %s", proxyType)
			targetLogger.Printf("Proxy pool: %s", proxyPool)
		}
	} else {
		proxyOptions = &proxy.Config{
			Type: proxy.ProxyType("none"),
		}
		targetLogger.Printf("Running without proxies (proxy-type=none)")
	}

	// 验证目标URL和攻击模式是否匹配
	isWebSocketTarget := strings.HasPrefix(strings.ToLower(target), "ws://") || strings.HasPrefix(strings.ToLower(target), "wss://")
	isWebSocketMode := strings.HasPrefix(mode, "ws-")

	if isWebSocketTarget && !isWebSocketMode {
		return fmt.Errorf("WebSocket目标(%s)必须使用WebSocket攻击模式", target)
	}

	if !isWebSocketTarget && isWebSocketMode {
		return fmt.Errorf("HTTP目标(%s)不能使用WebSocket攻击模式", target)
	}

	// 验证代理相关参数
	if proxyType == "local" && proxyFile != "" {
		return fmt.Errorf("使用本地代理(--proxy-type=local)时不能指定代理文件(--proxy-file)")
	}

	if uaType == "custom" && uaCustom == "" {
		return fmt.Errorf("使用自定义UA(--ua-type=custom)时必须指定UA文件(--ua-custom)")
	}

	// 验证WebSocket相关参数
	if !isWebSocketMode && (wsFrameSize != 1024 || wsCompression) {
		return fmt.Errorf("WebSocket参数(--ws-frame-size, --ws-compression)只能在WebSocket攻击模式下使用")
	}

	// 验证bypass和请求参数
	if mode == "" {
		if bypass != "" {
			return fmt.Errorf("绕过方法(--bypass)只能在指定攻击模式(-m/--mode)时使用")
		}
		if headers != "" || cookies != "" || postData != "" || referer != "" {
			return fmt.Errorf("请求参数(--headers, --cookies, --post-data, --referer)只能在指定攻击模式(-m/--mode)时使用")
		}
	}

	// 验证HTTP2相关参数
	if strings.HasPrefix(mode, "http2") || strings.HasPrefix(mode, "h2-") {
		if !strings.HasPrefix(strings.ToLower(target), "https://") {
			return fmt.Errorf("HTTP2攻击模式只能用于HTTPS目标")
		}
		// 自动启用HTTP2
		http2 = true
	}

	// 验证GET类型攻击模式不能使用--post-data参数
	if postData != "" {
		// 检查是否为GET类型的攻击模式
		getTypeModes := []string{
			"get-flood",       // 基本GET洪水攻击
			"head-flood",      // HEAD请求洪水攻击
			"options-flood",   // OPTIONS请求洪水攻击
			"trace-flood",     // TRACE请求洪水攻击
			"range-flood",     // Range请求洪水攻击
			"http2-get-flood", // HTTP/2 GET洪水攻击
			"smart-flood",     // 智能洪水攻击（当使用GET方法时）
		}

		for _, getMode := range getTypeModes {
			if mode == getMode {
				return fmt.Errorf("GET类型的攻击模式(%s)不能使用--post-data参数。\n"+
					"如果需要发送数据，请使用POST类型的攻击模式，例如:\n"+
					"  goto-http -u %s -m post-flood --post-data \"%s\"",
					mode, target, postData)
			}
		}

		// 检查method参数是否为GET类型
		if strings.ToUpper(method) == "GET" && mode != "post-flood" && !strings.HasPrefix(mode, "post") {
			return fmt.Errorf("使用GET方法时不能指定--post-data参数。\n"+
				"如果需要发送数据，请使用POST方法，例如:\n"+
				"  goto-http -u %s -X POST -m %s --post-data \"%s\"",
				target, mode, postData)
		}
	}

	// 在验证完参数后，处理随机占位符
	// 注意：不处理target，保留原始带占位符的URL
	// target = processPlaceholders(target)
	method = processPlaceholders(method)
	headers = processPlaceholders(headers)
	cookies = processPlaceholders(cookies)
	postData = processPlaceholders(postData)
	referer = processPlaceholders(referer)

	// 确保日志中打印处理后的参数值
	if debug {
		// Initialize targetLogger if it's nil
		if targetLogger == nil {
			targetLogger = log.New(os.Stdout, "[TARGET] ", log.Ldate|log.Ltime|log.Lmicroseconds)
		}

		targetLogger.Printf("Debug: Processed command line arguments:")
		targetLogger.Printf("  Target (原始携带随机变量): %s", target)
		targetLogger.Printf("  Method: %s", method)
		targetLogger.Printf("  Headers: %s", headers)
		targetLogger.Printf("  Cookies: %s", cookies)
		targetLogger.Printf("  Post data: %s", postData)
		targetLogger.Printf("  Referer: %s", referer)
	}

	// 处理headers
	customHeaders := make(map[string][]string)
	if headers != "" {
		for _, line := range strings.Split(headers, ";") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				customHeaders[key] = append(customHeaders[key], value)
			}
		}
	}

	// 如果设置了referer，添加到headers中
	if referer != "" {
		customHeaders["Referer"] = []string{referer}
	}

	// 处理cookies
	var customCookies []*http.Cookie
	if cookies != "" {
		for _, cookie := range strings.Split(cookies, ";") {
			parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
			if len(parts) == 2 {
				customCookies = append(customCookies, &http.Cookie{
					Name:  strings.TrimSpace(parts[0]),
					Value: strings.TrimSpace(parts[1]),
				})
			}
		}
	}

	// 处理bypass方法
	var bypassMethods []string
	if bypass != "" {
		bypassMethods = strings.Split(bypass, ",")
		for i, method := range bypassMethods {
			bypassMethods[i] = strings.TrimSpace(method)
		}
	}

	// 创建攻击选项
	opts := &attack.Options{
		Target:         target,
		Method:         method,
		Duration:       time.Duration(duration) * time.Second,
		Rate:           rate,
		Workers:        workers,
		Mode:           mode,
		HTTP2:          http2,
		FollowRedirect: followRedirect,
		KeepAlive:      keepAlive,
		WSCompression:  wsCompression,
		WSFrameSize:    wsFrameSize,
		ProxyType:      proxyType,
		ProxyFile:      proxyFile,
		Debug:          debug,
		NoLogging:      guiMode, // GUI模式下禁用控制台日志
		ProxyOptions:   proxyOptions,
		Headers:        customHeaders,
		Cookies:        customCookies,
		Body:           postData,
		BypassMethods:  bypassMethods,
		UserAgent: &useragent.Config{
			Type:       uaType,
			CustomFile: uaCustom,
		},
		RawTarget:  target,
		RawHeaders: customHeaders,
		RawCookies: customCookies,
		RawBody:    postData,
		BypassConfig: &attack.BypassConfig{
			CustomHeaders: make(map[string]string),
			TLSConfig:     &tls.Config{},
			DelayMin:      time.Duration(interval) * time.Millisecond,
			DelayMax:      time.Duration(interval*2) * time.Millisecond,
			RetryCount:    3,
			UserAgents:    []string{},
		},
		// 只保留一个超时设置
		Timeout: time.Duration(timeout) * time.Second,
	}

	// 创建攻击实例
	atk, err := attack.NewAttack(opts)
	if err != nil {
		return fmt.Errorf("failed to create attack: %v", err)
	}

	// GUI模式处理
	if guiMode {
		// 设置环境变量，标记为GUI模式
		os.Setenv("NO_LOGGING", "true")

		var dashErr error
		globalDashboard, dashErr = termui.NewDashboard()
		if dashErr != nil {
			return fmt.Errorf("failed to create dashboard: %v", dashErr)
		}
		defer globalDashboard.Stop()

		// 初始化状态
		globalDashboard.SetTarget(target)
		globalDashboard.SetMode(mode)
		globalDashboard.SetDuration(duration)
		globalDashboard.SetJobParams(workers, interval, rate, referer, headers, cookies, postData, proxyType, uaType, bypass)
		globalDashboard.HandleSignals()

		// 启动统计更新协程
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond) // 修改为每200毫秒更新一次，更快地捕获随机URL变化
			defer ticker.Stop()

			// 添加实际的服务器和IP数据跟踪
			realServers := []map[string]interface{}{}

			for {
				select {
				case <-ticker.C:
					// 获取真实统计数据
					statsMap := atk.GetStats()
					if statsMap != nil {
						// 打印调试信息，检查statsMap中的关键字段
						fmt.Printf("[DEBUG] GetStats returned: total=%v, currentRPS=%v, responseTime=%v\n",
							statsMap["total"], statsMap["currentRPS"], statsMap["avgRt"])
						fmt.Printf("[DEBUG] Network stats: bandwidth=%v, totalTraffic=%v, uploadSpeed=%v, downloadSpeed=%v\n",
							statsMap["bandwidth"], statsMap["totalTraffic"], statsMap["uploadSpeed"], statsMap["downloadSpeed"])
						fmt.Printf("[DEBUG] Bytes stats: bytesIn=%v, bytesOut=%v\n",
							statsMap["bytesIn"], statsMap["bytesOut"])
						fmt.Printf("[DEBUG] Stats keys: %v\n", getKeysString(statsMap))

						// 确保真实数据中包含必要的参数
						if _, ok := statsMap["mode"]; !ok {
							statsMap["mode"] = mode
						}
						if _, ok := statsMap["duration"]; !ok {
							statsMap["duration"] = duration
						}
						if _, ok := statsMap["works"]; !ok {
							statsMap["works"] = workers
						}
						if _, ok := statsMap["interval"]; !ok {
							statsMap["interval"] = interval
						}
						if _, ok := statsMap["rates"]; !ok {
							statsMap["rates"] = rate
						}

						// 计算并添加RPS数据 - 使用正确的字段名
						if total, ok := statsMap["total"].(uint64); ok && total > 0 {
							if startTime, ok := statsMap["start_time"].(time.Time); ok {
								elapsed := time.Since(startTime).Seconds()
								if elapsed > 0 {
									rps := float64(total) / elapsed
									statsMap["currentRPS"] = rps
									fmt.Printf("[DEBUG] Calculated RPS: %v (total=%v, elapsed=%v)\n",
										rps, total, elapsed)
								}
							} else {
								fmt.Printf("[DEBUG] start_time not found or wrong type: %T %v\n",
									statsMap["start_time"], statsMap["start_time"])
							}
						} else if total, ok := statsMap["total"].(float64); ok && total > 0 {
							// 尝试float64类型
							if startTime, ok := statsMap["start_time"].(time.Time); ok {
								elapsed := time.Since(startTime).Seconds()
								if elapsed > 0 {
									rps := total / elapsed
									statsMap["currentRPS"] = rps
									fmt.Printf("[DEBUG] Calculated RPS (float64): %v\n", rps)
								}
							}
						} else {
							fmt.Printf("[DEBUG] total not found or wrong type: %T %v\n",
								statsMap["total"], statsMap["total"])
						}

						// 添加响应时间数据 - 使用正确的字段名
						if avgRt, ok := statsMap["avgRt"].(float64); ok && avgRt > 0 {
							statsMap["responseTime"] = avgRt
							fmt.Printf("[DEBUG] Using avgRt: %v\n", avgRt)
						} else {
							fmt.Printf("[DEBUG] avgRt not found or wrong type: %T %v\n",
								statsMap["avgRt"], statsMap["avgRt"])
						}

						// 确保totalRequests字段存在 - 用于target count
						if _, ok := statsMap["totalRequests"]; !ok {
							if total, ok := statsMap["total"].(uint64); ok {
								statsMap["totalRequests"] = total
								fmt.Printf("[DEBUG] Set totalRequests from total: %v\n", total)
							} else if total, ok := statsMap["total"].(float64); ok {
								statsMap["totalRequests"] = uint64(total)
								fmt.Printf("[DEBUG] Set totalRequests from total (float64): %v\n", total)
							}
						}

						// 确保requestOK和requestFail字段存在
						if _, ok := statsMap["requestOK"]; !ok {
							if success, ok := statsMap["success"].(uint64); ok {
								statsMap["requestOK"] = success
								fmt.Printf("[DEBUG] Set requestOK from success: %v\n", success)
							} else if success, ok := statsMap["success"].(float64); ok {
								statsMap["requestOK"] = uint64(success)
								fmt.Printf("[DEBUG] Set requestOK from success (float64): %v\n", success)
							}
						}

						if _, ok := statsMap["requestFail"]; !ok {
							if failed, ok := statsMap["failed"].(uint64); ok {
								statsMap["requestFail"] = failed
								fmt.Printf("[DEBUG] Set requestFail from failed: %v\n", failed)
							} else if failed, ok := statsMap["failed"].(float64); ok {
								statsMap["requestFail"] = uint64(failed)
								fmt.Printf("[DEBUG] Set requestFail from failed (float64): %v\n", failed)
							}
						}

						// 添加网络统计数据 - 使用已有的字段
						if bandwidth, ok := statsMap["bandwidth"].(float64); ok && bandwidth > 0 {
							fmt.Printf("[DEBUG] Using existing bandwidth: %v\n", bandwidth)
						} else {
							fmt.Printf("[DEBUG] bandwidth not found or wrong type: %T %v\n",
								statsMap["bandwidth"], statsMap["bandwidth"])
						}

						if totalTraffic, ok := statsMap["totalTraffic"].(float64); ok && totalTraffic > 0 {
							fmt.Printf("[DEBUG] Using existing totalTraffic: %v\n", totalTraffic)
						} else {
							fmt.Printf("[DEBUG] totalTraffic not found or wrong type: %T %v\n",
								statsMap["totalTraffic"], statsMap["totalTraffic"])
						}

						if uploadSpeed, ok := statsMap["uploadSpeed"].(float64); ok && uploadSpeed > 0 {
							fmt.Printf("[DEBUG] Using existing uploadSpeed: %v\n", uploadSpeed)
						} else {
							fmt.Printf("[DEBUG] uploadSpeed not found or wrong type: %T %v\n",
								statsMap["uploadSpeed"], statsMap["uploadSpeed"])
						}

						if downloadSpeed, ok := statsMap["downloadSpeed"].(float64); ok && downloadSpeed > 0 {
							fmt.Printf("[DEBUG] Using existing downloadSpeed: %v\n", downloadSpeed)
						} else {
							fmt.Printf("[DEBUG] downloadSpeed not found or wrong type: %T %v\n",
								statsMap["downloadSpeed"], statsMap["downloadSpeed"])
						}

						// 从真实数据中提取服务器信息
						if serversList, ok := statsMap["servers"]; ok {
							if servers, ok := serversList.([]map[string]interface{}); ok {
								realServers = servers
							}
						}

						// 从lastRequest中收集真实服务器数据
						if lastReq, ok := statsMap["lastRequest"]; ok {
							if lastReqMap, ok := lastReq.(map[string]interface{}); ok {
								// 打印当前请求中的URL，验证是否包含随机值
								if urlVal, ok := lastReqMap["url"]; ok {
									fmt.Printf("[DEBUG] UI 接收到的lastRequest URL: %v\n", urlVal)
								}

								// 确保获取到了真实的服务器和IP信息
								if server, ok := lastReqMap["server"]; ok && server != nil && server.(string) != "" {
									if ip, ok := lastReqMap["ip"]; ok && ip != nil && ip.(string) != "" {
										ipStr := ip.(string)

										// 检查IP是否是有效的IP地址 (不是域名)
										if !strings.ContainsAny(ipStr, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
											ipStr != "" && ipStr != "unknown" && ipStr != "---" {

											// 验证IP地址格式
											parts := strings.Split(ipStr, ".")
											validIP := true

											if len(parts) == 4 {
												for _, part := range parts {
													num, err := strconv.Atoi(part)
													if err != nil || num < 0 || num > 255 {
														validIP = false
														break
													}
												}

												if validIP {
													// 添加到realServers以保持跟踪
													serverEntry := map[string]interface{}{
														"server": server,
														"ip":     ipStr,
													}

													// 添加其他可能的字段
													if code, ok := lastReqMap["code"]; ok {
														serverEntry["code"] = code
													}
													if latency, ok := lastReqMap["latency"]; ok {
														serverEntry["latency"] = latency
													}
													if size, ok := lastReqMap["size"]; ok {
														serverEntry["size"] = size
													}

													// 添加到服务器列表
													realServers = append(realServers, serverEntry)

													// 限制realServers的大小，只保留最新的50条记录
													if len(realServers) > 50 {
														realServers = realServers[len(realServers)-50:]
													}

													// 将收集到的服务器数据添加到statsMap中
													statsMap["servers"] = realServers
												}
											}
										}
									}
								}
							}
						}

						// 将收集到的数据传递给dashboard更新UI
						globalDashboard.UpdateStats(statsMap)
					}

					// 只打印调试信息，不添加或使用模拟数据
					fmt.Printf("[STATS_DEBUG] Sent real stats to dashboard\n")
				}
			}
		}()

		// 启动攻击
		go func() {
			if atkErr := atk.Start(ctx); atkErr != nil {
				fmt.Fprintf(errorLogFile, "Attack failed: %v\n", atkErr)
			}
		}()

		// 在主线程中运行UI
		if uiErr := globalDashboard.Start(); uiErr != nil {
			fmt.Fprintf(errorLogFile, "Dashboard error: %v\n", uiErr)
			return fmt.Errorf("dashboard error: %v", uiErr)
		}
	} else {
		// 非GUI模式
		fmt.Printf(banner, version)
		if atkErr := atk.Start(ctx); atkErr != nil {
			errorLogger.Printf("Attack failed: %v", atkErr)
			return fmt.Errorf("failed to start attack: %v", atkErr)
		}
		<-ctx.Done()
	}

	return nil
}

// getKeysString 返回map中所有键的字符串表示
func getKeysString(m map[string]interface{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
