package proxy

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

// ProxyCLI handles command line interface for proxy configuration
type ProxyCLI struct {
	ProxyType        string        // 代理类型: none, local, api
	ProxyFile        string        // 代理文件路径
	ProxyAPIPool     string        // 代理API池选择，格式：all 或 pool1,pool2,pool3
	ProxyCountries   string        // 代理国家/地区列表，逗号分隔
	ProxyFailover    bool          // 代理故障转移
	ProxyTimeout     time.Duration // 代理超时时间
	ProxyRetry       int           // 代理重试次数
	ProxyValidate    bool          // 验证代理
	ProxyValidateURL string        // 代理验证URL
}

// NewProxyCLI creates a new CLI instance
func NewProxyCLI() *ProxyCLI {
	return &ProxyCLI{
		ProxyType:        "none",
		ProxyFile:        "config/proxies.txt",
		ProxyAPIPool:     "all",
		ProxyTimeout:     10 * time.Second,
		ProxyRetry:       3,
		ProxyFailover:    true,
		ProxyValidate:    true,
		ProxyValidateURL: "http://www.baidu.com",
	}
}

// ParseFlags parses command line flags
func (c *ProxyCLI) ParseFlags(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)

	fs.StringVar(&c.ProxyType, "proxy-type", c.ProxyType, "代理类型: none, local, api")
	fs.StringVar(&c.ProxyFile, "proxy-file", c.ProxyFile, "代理文件路径")
	fs.StringVar(&c.ProxyAPIPool, "proxy-api-pool", c.ProxyAPIPool, "代理API池选择，格式：all 或 pool1,pool2,pool3")
	fs.StringVar(&c.ProxyCountries, "proxy-countries", c.ProxyCountries, "代理国家/地区列表，逗号分隔")
	fs.BoolVar(&c.ProxyFailover, "proxy-failover", c.ProxyFailover, "代理故障转移")
	fs.DurationVar(&c.ProxyTimeout, "proxy-timeout", c.ProxyTimeout, "代理超时时间")
	fs.IntVar(&c.ProxyRetry, "proxy-retry", c.ProxyRetry, "代理重试次数")
	fs.BoolVar(&c.ProxyValidate, "proxy-validate", c.ProxyValidate, "验证代理")
	fs.StringVar(&c.ProxyValidateURL, "proxy-validate-url", c.ProxyValidateURL, "代理验证URL")

	return fs.Parse(args)
}

// GetSelectedPools returns the selected pool names
func (c *ProxyCLI) GetSelectedPools() []string {
	if c.ProxyAPIPool == "" || c.ProxyAPIPool == "all" {
		return []string{"all"}
	}
	return strings.Split(c.ProxyAPIPool, ",")
}

// ValidatePoolNames validates the selected pool names
func (c *ProxyCLI) ValidatePoolNames(availablePools []string) error {
	if c.ProxyAPIPool == "" || c.ProxyAPIPool == "all" {
		return nil
	}

	selectedPools := c.GetSelectedPools()
	for _, selected := range selectedPools {
		found := false
		for _, available := range availablePools {
			if selected == available {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid pool name: %s", selected)
		}
	}
	return nil
}

// ToConfig converts CLI parameters to Config
func (c *ProxyCLI) ToConfig() *Config {
	config := &Config{
		Type:          ProxyType(c.ProxyType),
		File:          c.ProxyFile,
		Timeout:       int(c.ProxyTimeout.Seconds()),
		RetryInterval: c.ProxyRetry,
		MaxFails:      3, // 默认3次
	}

	// 如果指定了国家/地区，添加过滤规则
	if c.ProxyCountries != "" {
		countries := strings.Split(c.ProxyCountries, ",")
		for i := range countries {
			countries[i] = strings.TrimSpace(countries[i])
		}
		config.Countries = countries
	}

	return config
}

// GetCountries returns the list of selected countries
func (c *ProxyCLI) GetCountries() []string {
	if c.ProxyCountries == "" {
		return nil
	}
	countries := strings.Split(c.ProxyCountries, ",")
	for i := range countries {
		countries[i] = strings.TrimSpace(countries[i])
	}
	return countries
}

// IsFailoverEnabled returns whether failover is enabled
func (c *ProxyCLI) IsFailoverEnabled() bool {
	return c.ProxyFailover
}

// ShouldValidate returns whether proxy validation is enabled
func (c *ProxyCLI) ShouldValidate() bool {
	return c.ProxyValidate
}
