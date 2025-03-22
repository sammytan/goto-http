package proxy

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SupportedProtocols defines the list of supported proxy protocols
var SupportedProtocols = []string{
	"http://",
	"https://",
	"socks5://",
}

// ProxyType defines the type of proxy
type ProxyType string

const (
	TYPE_HTTP   ProxyType = "http"
	TYPE_HTTPS  ProxyType = "https"
	TYPE_SOCKS5 ProxyType = "socks5"
	TYPE_LOCAL  ProxyType = "local"
	TYPE_API    ProxyType = "api"
	TYPE_SERVER ProxyType = "server"
	TYPE_NONE   ProxyType = "none"
	TYPE_FILE   ProxyType = "file"
)

// ProxyStatus defines the status of a proxy
type ProxyStatus string

const (
	STATUS_ACTIVE   ProxyStatus = "active"
	STATUS_INACTIVE ProxyStatus = "inactive"
	STATUS_FAILED   ProxyStatus = "failed"
)

// FilterRule 过滤规则
type FilterRule struct {
	Type      string   `json:"type"`      // country, region, latency, uptime
	Operation string   `json:"operation"` // equals, not_equals, in, not_in, gt, lt
	Values    []string `json:"values"`
}

// ProxyStats tracks proxy usage statistics
type ProxyStats struct {
	Total        int               `json:"total"`         // Total requests
	Active       int               `json:"active"`        // Active proxies
	CountryStats map[string]int    `json:"country_stats"` // Stats by country
	TypeStats    map[ProxyType]int `json:"type_stats"`    // Stats by type
}

// Proxy represents a proxy server
type Proxy struct {
	URL       string            `json:"url"`        // Full proxy URL
	Protocol  string            `json:"protocol"`   // Protocol (http, https, socks5)
	Host      string            `json:"host"`       // Host address
	Type      ProxyType         `json:"type"`       // Proxy type
	Status    ProxyStatus       `json:"status"`     // Current status
	Country   string            `json:"country"`    // Country code
	LastUsed  time.Time         `json:"last_used"`  // Last used timestamp
	LastCheck time.Time         `json:"last_check"` // Last check timestamp
	Latency   int64             `json:"latency"`    // Latency in milliseconds
	TotalUsed int64             `json:"total_used"` // Total times used
	Failures  int               `json:"failures"`   // Failure count
	Username  string            `json:"username"`   // Username for authentication
	Password  string            `json:"password"`   // Password for authentication
	Uptime    float64           `json:"uptime"`     // Uptime percentage
	Transport http.RoundTripper `json:"-"`          // Transport for making requests
}

// APIResponseFormat 定义API响应格式
type APIResponseFormat string

const (
	FORMAT_TEXT APIResponseFormat = "txt"
	FORMAT_JSON APIResponseFormat = "json"
)

// GenericAPIResponse 通用API响应结构
type GenericAPIResponse struct {
	Code      int         `json:"code"`
	Msg       string      `json:"msg"`
	Data      interface{} `json:"data"`
	RequestID string      `json:"request_id"`
}

// FlyProxyResponse FlyProxy平台的响应结构
type FlyProxyResponse struct {
	Code      int    `json:"code"`
	Msg       string `json:"msg"`
	RequestID string `json:"request_id"`
	Data      struct {
		List []string `json:"list"`
	} `json:"data"`
}

// ProxyProviderType defines the type of proxy provider
type ProxyProviderType string

const (
	PROVIDER_TYPE_API    ProxyProviderType = "api"    // API模式，需要先请求API获取代理列表
	PROVIDER_TYPE_SERVER ProxyProviderType = "server" // 代理服务器分发模式，直接请求
)

// ResponseFormat 定义API响应格式配置
type ResponseFormat struct {
	Format      string `yaml:"format"`       // 响应格式：json/txt
	SuccessCode int    `yaml:"success_code"` // 成功状态码
	Separator   string `yaml:"separator"`    // 分隔符
	// JSON格式特定配置
	JSONPath struct {
		Code      string `yaml:"code"`       // 状态码字段路径
		Message   string `yaml:"message"`    // 消息字段路径
		Data      string `yaml:"data"`       // 数据字段路径
		ProxyList string `yaml:"proxy_list"` // 代理列表字段路径
	} `yaml:"json_path"`
}

// Provider represents a proxy provider configuration
type Provider struct {
	Name             string            `yaml:"name"`             // 代理提供商名称
	Type             ProxyProviderType `yaml:"type"`             // 代理类型
	Enable           bool              `yaml:"enable"`           // 是否启用
	APIURL           string            `yaml:"api_url"`          // API地址
	Format           string            `yaml:"format"`           // 代理格式
	SupportCountrys  bool              `yaml:"support_countrys"` // 是否支持国家选择
	Countries        []string          `yaml:"countries"`        // 选择的国家
	CommandCountries []string          `yaml:"command_countries"`
	AttackDuration   int               `yaml:"attack_duration"`
	IsAllMode        bool              `yaml:"is_all_mode"`
	Params           struct {
		Name     string `yaml:"name"`
		Country  string `yaml:"country"`
		State    string `yaml:"state"`
		City     string `yaml:"city"`
		Format   string `yaml:"format"`
		Timeout  int    `yaml:"timeout"`
		TimeVal  int    `yaml:"time"`
		Num      int    `yaml:"num"`
		Protocol int    `yaml:"protocol"`
		LB       string `yaml:"lb"`
		UPID     string `yaml:"upid"`
		PT       int    `yaml:"pt"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Session  string `yaml:"session"`
		Life     int    `yaml:"life"`
		Area     string `yaml:"area"`
		AppKey   string `yaml:"app_key"`
	} `yaml:"params"` // 参数
}

// ProviderParams API请求参数
type ProviderParams struct {
	Timeout   int    `yaml:"timeout"`
	Anonymity string `yaml:"anonymity"`
	SSL       string `yaml:"ssl"`
	AppKey    string `yaml:"app_key"`
	Name      string `yaml:"name"`
	Format    string `yaml:"format"`
	Num       int    `yaml:"num"`
	Protocol  int    `yaml:"protocol"`
	PT        int    `yaml:"pt"`
	LB        string `yaml:"lb"`
	UPID      string `yaml:"upid"`
	Session   string `yaml:"session"`
	Life      int    `yaml:"life"`
	Area      string `yaml:"area"`
	Country   string `yaml:"country"`
	State     string `yaml:"state"`
	City      string `yaml:"city"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	TimeVal   int    `yaml:"time"`
}

// ResponseConfig API响应解析配置
type ResponseConfig struct {
	Format        string `yaml:"format"`          // 响应格式 (json/txt)
	SuccessCode   int    `yaml:"success_code"`    // 成功状态码
	DataPath      string `yaml:"data_path"`       // JSON数据路径 (例如: "data.list")
	Separator     string `yaml:"separator"`       // 文本格式分隔符
	ErrorCodePath string `yaml:"error_code_path"` // 错误码路径
	ErrorMsgPath  string `yaml:"error_msg_path"`  // 错误信息路径
}

// APIConfig API代理配置
type APIConfig struct {
	Version string `yaml:"version"`
	Proxy   struct {
		Enable    bool       `yaml:"enable"`
		Type      string     `yaml:"type"`
		Providers []Provider `yaml:"providers"`
		Settings  struct {
			Timeout         string `yaml:"timeout"`
			Interval        string `yaml:"interval"`
			MaxFails        int    `yaml:"max_fails"`
			RetryTimes      int    `yaml:"retry_times"`
			Failover        bool   `yaml:"failover"`
			ValidateEnable  bool   `yaml:"validate_enable"`
			ValidateURL     string `yaml:"validate_url"`
			ValidateTimeout string `yaml:"validate_timeout"`
		} `yaml:"settings"`
		Filters struct {
			Latency struct {
				Max int `yaml:"max"`
				Min int `yaml:"min"`
			} `yaml:"latency"`
			Uptime struct {
				Min int `yaml:"min"`
			} `yaml:"uptime"`
			SuccessRate struct {
				Min int `yaml:"min"`
			} `yaml:"success_rate"`
			Bandwidth struct {
				Min  int    `yaml:"min"`
				Unit string `yaml:"unit"`
			} `yaml:"bandwidth"`
		} `yaml:"filters"`
		Rotation struct {
			Enable   bool   `yaml:"enable"`
			Interval string `yaml:"interval"`
			Strategy string `yaml:"strategy"`
			MaxUses  int    `yaml:"max_uses"`
		} `yaml:"rotation"`
		Cache struct {
			Enable bool   `yaml:"enable"`
			Size   int    `yaml:"size"`
			TTL    string `yaml:"ttl"`
		} `yaml:"cache"`
	} `yaml:"proxy"`
}

// PoolConfig 定义代理池配置
type PoolConfig struct {
	URLs             []string               `yaml:"urls"`
	Method           string                 `yaml:"method"`
	Headers          map[string]string      `yaml:"headers"`
	Params           map[string]interface{} `yaml:"params"`
	Interval         int                    `yaml:"interval"`
	Timeout          int                    `yaml:"timeout"`
	CountryParamName string                 `yaml:"country_param_name"`
	ResponseFormat   struct {
		ProxyField   string `yaml:"proxy_field"`
		IPField      string `yaml:"ip_field"`
		PortField    string `yaml:"port_field"`
		CountryField string `yaml:"country_field"`
		TypeField    string `yaml:"type_field"`
	} `yaml:"response_format"`
}

// Config represents the proxy configuration
type Config struct {
	Type            ProxyType    `yaml:"type"`               // 代理类型
	File            string       `yaml:"file"`               // 本地代理文件路径
	APIPool         string       `yaml:"api_pool"`           // API代理池名称
	Countries       []string     `yaml:"countries"`          // 国家/地区限制
	FilterRules     []FilterRule `yaml:"filter_rules"`       // 过滤规则
	MaxFails        int          `yaml:"max_fails"`          // 最大失败次数
	RetryInterval   int          `yaml:"retry_interval"`     // 重试间隔(秒)
	Timeout         int          `yaml:"timeout"`            // 超时时间(秒)
	Retries         int          `yaml:"retries"`            // 重试次数
	CheckInterval   int          `yaml:"check_interval"`     // 检查间隔(秒)
	MaxFailures     int          `yaml:"max_failures"`       // 最大失败次数
	Protocols       []string     `yaml:"protocols"`          // 支持的协议
	API             string       `yaml:"api"`                // API 端点
	ValidateURL     string       `yaml:"validate_url"`       // 验证 URL
	ValidateEnable  bool         `yaml:"validate_enable"`    // 是否启用验证
	Proxies         []string     `json:"proxies"`            // 代理列表
	Providers       []Provider   `yaml:"providers"`          // 代理提供者列表
	MaxConns        int          `yaml:"max_conns"`          // 最大连接总数
	MaxConnsPerHost int          `yaml:"max_conns_per_host"` // 每个主机的最大连接数
}

// UpdateCountries 从命令行参数更新countries
func (p *Provider) UpdateCountries(countriesStr string) {
	if countriesStr == "" {
		return
	}
	// 清空命令行国家列表
	p.CommandCountries = nil
	// 解析命令行参数中的国家代码
	countries := strings.Split(countriesStr, ",")
	for _, country := range countries {
		if country = strings.TrimSpace(country); country != "" {
			p.CommandCountries = append(p.CommandCountries, country)
		}
	}
}

// GetRandomCountry 从可用的国家列表中随机获取一个国家
func (p *Provider) GetRandomCountry() string {
	// 优先使用命令行参数中的国家列表
	if len(p.CommandCountries) > 0 {
		return p.CommandCountries[rand.Intn(len(p.CommandCountries))]
	}
	// 其次使用配置文件中的国家列表
	if len(p.Countries) > 0 {
		return p.Countries[rand.Intn(len(p.Countries))]
	}
	// 最后使用配置中的默认值
	switch p.Type {
	case PROVIDER_TYPE_SERVER:
		return p.Params.Area
	case PROVIDER_TYPE_API:
		return p.Params.Country
	}
	return ""
}

// ProxyPool 代理池配置
type ProxyPool struct {
	Name        string            `json:"name"`
	URLs        []string          `json:"urls"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Params      map[string]string `json:"params"`
	Interval    time.Duration     `json:"interval"`
	Timeout     time.Duration     `json:"timeout"`
	MaxFailures int               `json:"max_failures"`
	RetryDelay  time.Duration     `json:"retry_delay"`
	FilterRules []FilterRule      `json:"filter_rules"`
}

// ToMap converts ProviderParams to a map[string]string
func (p *ProviderParams) ToMap() map[string]string {
	params := make(map[string]string)

	// 添加所有非零值参数
	if p.AppKey != "" {
		params["app_key"] = p.AppKey
	}
	if p.Name != "" {
		params["name"] = p.Name
	}
	if p.Format != "" {
		params["format"] = p.Format
	}
	if p.Num > 0 {
		params["num"] = strconv.Itoa(p.Num)
	}
	if p.Protocol > 0 {
		params["protocol"] = strconv.Itoa(p.Protocol)
	}
	if p.PT > 0 {
		params["pt"] = strconv.Itoa(p.PT)
	}
	if p.Life > 0 {
		params["life"] = strconv.Itoa(p.Life)
	}
	if p.TimeVal >= 0 {
		params["time"] = strconv.Itoa(p.TimeVal)
	}
	if p.UPID != "" {
		params["upid"] = p.UPID
	}
	if p.LB != "" {
		params["lb"] = p.LB
	}
	if p.Username != "" {
		params["username"] = p.Username
	}
	if p.Password != "" {
		params["password"] = p.Password
	}
	if p.Session != "" {
		params["session"] = p.Session
	}
	if p.Area != "" {
		params["area"] = p.Area
	}
	if p.Country != "" {
		params["country"] = p.Country
	}
	if p.State != "" {
		params["state"] = p.State
	}
	if p.City != "" {
		params["city"] = p.City
	}

	return params
}

// GetParams returns the parameters as a map
func (p *Provider) GetParams() map[string]string {
	params := make(map[string]string)

	// 添加所有非空参数
	if p.Params.AppKey != "" {
		params["app_key"] = p.Params.AppKey
	}
	if p.Params.Name != "" {
		params["name"] = p.Params.Name
	}
	if p.Params.Format != "" {
		params["format"] = p.Params.Format
	}
	if p.Params.Num > 0 {
		params["num"] = strconv.Itoa(p.Params.Num)
	}
	if p.Params.Protocol > 0 {
		params["protocol"] = strconv.Itoa(p.Params.Protocol)
	}
	if p.Params.PT > 0 {
		params["pt"] = strconv.Itoa(p.Params.PT)
	}
	if p.Params.Life > 0 {
		params["life"] = strconv.Itoa(p.Params.Life)
	}
	if p.Params.TimeVal >= 0 {
		params["time"] = strconv.Itoa(p.Params.TimeVal)
	}
	if p.Params.UPID != "" {
		params["upid"] = p.Params.UPID
	}
	if p.Params.LB != "" {
		params["lb"] = p.Params.LB
	}
	if p.Params.Username != "" {
		params["username"] = p.Params.Username
	}
	if p.Params.Password != "" {
		params["password"] = p.Params.Password
	}
	if p.Params.Session != "" {
		params["session"] = p.Params.Session
	}
	if p.Params.Area != "" {
		params["area"] = p.Params.Area
	}
	if p.Params.Country != "" {
		params["country"] = p.Params.Country
	}
	if p.Params.State != "" {
		params["state"] = p.Params.State
	}
	if p.Params.City != "" {
		params["city"] = p.Params.City
	}

	return params
}

// GetTimeout returns the timeout value
func (p *Provider) GetTimeout() int {
	if p.Params.Timeout > 0 {
		return p.Params.Timeout
	}
	return 30000 // 默认30秒
}

// GetCountry returns the country value
func (p *Provider) GetCountry() string {
	return p.Params.Country
}
