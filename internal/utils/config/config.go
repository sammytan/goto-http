package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"goto-http/internal/attack"
)

// AttackConfig 攻击配置
type AttackConfig struct {
	// 基础参数
	URL              string
	Concurrency      int
	Duration         int
	Interval         int
	MaxConns         int
	MaxConnsPerHost  int
	CPUPercentage    int
	MemoryPercentage int
	MaxFiles         int

	// 攻击参数
	AttackMode     string
	BypassMode     string
	ProxyType      string
	ProxyFile      string
	ProxyAPIPool   string
	ProxyCountries []string
	UAType         string

	// 其他参数
	Debug   bool
	Version bool
}

// ProxyAPIConfig API代理配置
type ProxyAPIConfig struct {
	URLs             []string               `json:"urls"`
	Method           string                 `json:"method"`
	Headers          map[string]string      `json:"headers"`
	Params           map[string]interface{} `json:"params"`
	Interval         int                    `json:"interval"`
	Timeout          int                    `json:"timeout"`
	CountryParamName string                 `json:"country_param_name"`
	ResponseFormat   struct {
		ProxyField   string `json:"proxy_field"`
		IPField      string `json:"ip_field"`
		PortField    string `json:"port_field"`
		CountryField string `json:"country_field"`
		TypeField    string `json:"type_field"`
	} `json:"response_format"`
}

// APIConfig API配置文件
type APIConfig struct {
	Pools map[string]ProxyAPIConfig `json:"pools"`
}

// LoadAPIConfig 加载API配置
func LoadAPIConfig(configPath string) (*APIConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read API config file: %v", err)
	}

	var config APIConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse API config: %v", err)
	}

	return &config, nil
}

// LoadProxies 加载代理列表
func LoadProxies(proxyFile string) ([]string, error) {
	data, err := os.ReadFile(proxyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy file: %v", err)
	}

	var proxies []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	return proxies, nil
}

// ValidateConfig validates the attack configuration
func ValidateConfig(opts *attack.Options) error {
	// 检查目标URL
	if opts.Target == "" {
		return fmt.Errorf("target URL is required, use -target flag to specify")
	}

	// 检查并发数
	if opts.Workers < 1 {
		return fmt.Errorf("workers must be greater than 0")
	}

	// 检查持续时间
	if opts.Duration <= 0 {
		return fmt.Errorf("duration must be greater than 0")
	}

	// 检查攻击模式
	validModes := []string{
		"get-flood", "post-flood", "head-flood", "options-flood",
		"trace-flood", "mixed-method", "body-flood", "chunk-flood",
		"expect-flood", "range-flood", "multipart-flood", "slowloris",
		"slowpost", "http2flood", "http2priority", "http2rst",
		"http2goaway", "h2-window-update", "h2-ping-flood",
		"h2-push-promise", "h2-stream-dep", "h2-settings-flood",
		"h2-header-table", "ws-flood", "ws-fragment", "ws-compress-amp",
		"ws-ping-flood", "ws-frame-masking", "ws-connection-flood",
		"ws-protocol-abuse", "ws-extension-abuse", "protocol-confusion",
		"upgrade-abuse", "websocket-tunnel", "http-tunnel", "smart-flood",
		"mixed-protocol", "resource-exhaust", "connection-abuse",
		"cache-poison", "dns-rebinding", "request-smuggling",
		"parameter-pollution",
	}

	modeValid := false
	for _, mode := range validModes {
		if opts.Mode == mode {
			modeValid = true
			break
		}
	}

	if !modeValid {
		return fmt.Errorf("invalid attack mode: %s\nValid modes are: %v", opts.Mode, validModes)
	}

	// 检查代理配置
	if opts.ProxyType != "none" && opts.ProxyType != "local" && opts.ProxyType != "api" {
		return fmt.Errorf("invalid proxy type: %s\nValid types are: none, local, api", opts.ProxyType)
	}

	// 检查本地代理文件
	if opts.ProxyType == "local" {
		if opts.ProxyFile == "" {
			opts.ProxyFile = "configs/proxies.txt" // 设置默认值
		}
		if _, err := os.Stat(opts.ProxyFile); err != nil {
			return fmt.Errorf("proxy file not found: %s\nPlease create the file or specify a valid path with -proxy-file flag\nExample proxy file format:\nhttp://1.2.3.4:8080\nsocks5://5.6.7.8:1080", opts.ProxyFile)
		}
	}

	// 检查API代理配置
	if opts.ProxyType == "api" {
		// 检查API配置文件
		apiConfigPath := "configs/api_proxy.yaml"
		if _, err := os.Stat(apiConfigPath); err != nil {
			return fmt.Errorf("API proxy config file not found: %s\nPlease create the file using the example in configs/api_proxy.example.yaml", apiConfigPath)
		}
	}

	return nil
}

// ParseCountries 解析国家代码
func ParseCountries(countries string) []string {
	if countries == "" {
		return nil
	}
	return strings.Split(strings.ToUpper(countries), ",")
}

// EnsureConfigDirs 确保配置目录存在
func EnsureConfigDirs() error {
	dirs := []string{
		"config",
		"logs",
		"data",
		"data/temp",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	return nil
}

// SaveConfig 保存配置到文件
func SaveConfig(config *AttackConfig, filename string) error {
	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// LoadConfig 从文件加载配置
func LoadConfig(filename string) (*AttackConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config AttackConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	return &config, nil
}
