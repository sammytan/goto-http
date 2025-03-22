package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v2"
)

// Config 配置结构
type Config struct {
	// 基本配置
	Version string `json:"version" yaml:"version"`
	Debug   bool   `json:"debug" yaml:"debug"`

	// GUI配置
	GUI struct {
		Web struct {
			Enable bool   `json:"enable" yaml:"enable"`
			Port   string `json:"port" yaml:"port"`
		} `json:"web" yaml:"web"`
		Terminal struct {
			Enable bool `json:"enable" yaml:"enable"`
		} `json:"terminal" yaml:"terminal"`
	} `json:"gui" yaml:"gui"`

	// 系统配置
	System struct {
		MaxProcs int    `json:"max_procs" yaml:"max_procs"`
		MaxFiles uint64 `json:"max_files" yaml:"max_files"`
		CPULimit int    `json:"cpu_limit" yaml:"cpu_limit"`
		MemLimit uint64 `json:"mem_limit" yaml:"mem_limit"`
	} `json:"system" yaml:"system"`

	// 攻击配置
	Attack struct {
		Target    string            `json:"target" yaml:"target"`
		Method    string            `json:"method" yaml:"method"`
		Duration  time.Duration     `json:"duration" yaml:"duration"`
		Rate      int               `json:"rate" yaml:"rate"`
		Workers   int               `json:"workers" yaml:"workers"`
		Timeout   time.Duration     `json:"timeout" yaml:"timeout"`
		Mode      string            `json:"mode" yaml:"mode"`
		Headers   map[string]string `json:"headers" yaml:"headers"`
		UserAgent struct {
			Type       string `json:"type" yaml:"type"`
			CustomFile string `json:"custom_file" yaml:"custom_file"`
		} `json:"user_agent" yaml:"user_agent"`
		Body           string `json:"body" yaml:"body"`
		HTTP2          bool   `json:"http2" yaml:"http2"`
		KeepAlive      bool   `json:"keep_alive" yaml:"keep_alive"`
		FollowRedirect bool   `json:"follow_redirect" yaml:"follow_redirect"`
		// WebSocket设置
		WSFrameSize   int  `json:"ws_frame_size" yaml:"ws_frame_size"`
		WSCompression bool `json:"ws_compression" yaml:"ws_compression"`
	} `json:"attack" yaml:"attack"`

	// 代理配置
	Proxy struct {
		Enable    bool   `json:"enable" yaml:"enable"`
		Type      string `json:"type" yaml:"type"`
		Providers []struct {
			Name      string                 `json:"name" yaml:"name"`
			APIURL    string                 `json:"api_url" yaml:"api_url"`
			APIKey    string                 `json:"api_key" yaml:"api_key"`
			Weight    int                    `json:"weight" yaml:"weight"`
			Countries []string               `json:"countries" yaml:"countries"`
			Protocols []string               `json:"protocols" yaml:"protocols"`
			Params    map[string]interface{} `json:"params" yaml:"params"`
		} `json:"providers" yaml:"providers"`
		Settings struct {
			Timeout         time.Duration `json:"timeout" yaml:"timeout"`
			Interval        time.Duration `json:"interval" yaml:"interval"`
			MaxFails        int           `json:"max_fails" yaml:"max_fails"`
			RetryTimes      int           `json:"retry_times" yaml:"retry_times"`
			Failover        bool          `json:"failover" yaml:"failover"`
			ValidateEnable  bool          `json:"validate_enable" yaml:"validate_enable"`
			ValidateURL     string        `json:"validate_url" yaml:"validate_url"`
			ValidateTimeout time.Duration `json:"validate_timeout" yaml:"validate_timeout"`
			MaxConns        int           `json:"max_conns" yaml:"max_conns"`                   // 最大连接总数
			MaxConnsPerHost int           `json:"max_conns_per_host" yaml:"max_conns_per_host"` // 每个主机的最大连接数
		} `json:"settings" yaml:"settings"`
		Filters struct {
			Latency struct {
				Max int `json:"max" yaml:"max"`
				Min int `json:"min" yaml:"min"`
			} `json:"latency" yaml:"latency"`
			Uptime struct {
				Min float64 `json:"min" yaml:"min"`
			} `json:"uptime" yaml:"uptime"`
			SuccessRate struct {
				Min float64 `json:"min" yaml:"min"`
			} `json:"success_rate" yaml:"success_rate"`
			Bandwidth struct {
				Min  float64 `json:"min" yaml:"min"`
				Unit string  `json:"unit" yaml:"unit"`
			} `json:"bandwidth" yaml:"bandwidth"`
		} `json:"filters" yaml:"filters"`
		Rotation struct {
			Enable   bool          `json:"enable" yaml:"enable"`
			Interval time.Duration `json:"interval" yaml:"interval"`
			Strategy string        `json:"strategy" yaml:"strategy"`
			MaxUses  int           `json:"max_uses" yaml:"max_uses"`
		} `json:"rotation" yaml:"rotation"`
		Cache struct {
			Enable bool          `json:"enable" yaml:"enable"`
			Size   int           `json:"size" yaml:"size"`
			TTL    time.Duration `json:"ttl" yaml:"ttl"`
		} `json:"cache" yaml:"cache"`
	} `json:"proxy" yaml:"proxy"`

	// 绕过配置
	Bypass struct {
		Methods       []string          `json:"methods" yaml:"methods"`
		CustomHeaders map[string]string `json:"custom_headers" yaml:"custom_headers"`
		RandomizeUA   bool              `json:"randomize_ua" yaml:"randomize_ua"`
		DelayMin      time.Duration     `json:"delay_min" yaml:"delay_min"`
		DelayMax      time.Duration     `json:"delay_max" yaml:"delay_max"`
		RetryCount    int               `json:"retry_count" yaml:"retry_count"`
		RetryInterval time.Duration     `json:"retry_interval" yaml:"retry_interval"`
	} `json:"bypass" yaml:"bypass"`

	// 日志配置
	Log struct {
		File   string `json:"file" yaml:"file"`
		Level  string `json:"level" yaml:"level"`
		Format string `json:"format" yaml:"format"`
	} `json:"log" yaml:"log"`

	// 监控配置
	Monitor struct {
		Enable   bool     `json:"enable" yaml:"enable"`
		Interval duration `json:"interval" yaml:"interval"`
		Metrics  []string `json:"metrics" yaml:"metrics"`
		Alerts   []struct {
			Name      string   `json:"name" yaml:"name"`
			Metric    string   `json:"metric" yaml:"metric"`
			Threshold float64  `json:"threshold" yaml:"threshold"`
			Duration  duration `json:"duration" yaml:"duration"`
			Action    string   `json:"action" yaml:"action"`
		} `json:"alerts" yaml:"alerts"`
	} `json:"monitor" yaml:"monitor"`
}

// ProxyConfig 代理配置结构
type ProxyConfig struct {
	Version string `json:"version" yaml:"version"`
	Proxy   struct {
		Enable    bool   `json:"enable" yaml:"enable"`
		Type      string `json:"type" yaml:"type"`
		Providers []struct {
			Name      string                 `json:"name" yaml:"name"`
			APIURL    string                 `json:"api_url" yaml:"api_url"`
			APIKey    string                 `json:"api_key" yaml:"api_key"`
			Weight    int                    `json:"weight" yaml:"weight"`
			Countries []string               `json:"countries" yaml:"countries"`
			Protocols []string               `json:"protocols" yaml:"protocols"`
			Params    map[string]interface{} `json:"params" yaml:"params"`
		} `json:"providers" yaml:"providers"`
		Settings struct {
			Timeout         time.Duration `json:"timeout" yaml:"timeout"`
			Interval        time.Duration `json:"interval" yaml:"interval"`
			MaxFails        int           `json:"max_fails" yaml:"max_fails"`
			RetryTimes      int           `json:"retry_times" yaml:"retry_times"`
			Failover        bool          `json:"failover" yaml:"failover"`
			ValidateEnable  bool          `json:"validate_enable" yaml:"validate_enable"`
			ValidateURL     string        `json:"validate_url" yaml:"validate_url"`
			ValidateTimeout time.Duration `json:"validate_timeout" yaml:"validate_timeout"`
			MaxConns        int           `json:"max_conns" yaml:"max_conns"`                   // 最大连接总数
			MaxConnsPerHost int           `json:"max_conns_per_host" yaml:"max_conns_per_host"` // 每个主机的最大连接数
		} `json:"settings" yaml:"settings"`
		Filters struct {
			Latency struct {
				Max int `json:"max" yaml:"max"`
				Min int `json:"min" yaml:"min"`
			} `json:"latency" yaml:"latency"`
			Uptime struct {
				Min float64 `json:"min" yaml:"min"`
			} `json:"uptime" yaml:"uptime"`
			SuccessRate struct {
				Min float64 `json:"min" yaml:"min"`
			} `json:"success_rate" yaml:"success_rate"`
			Bandwidth struct {
				Min  float64 `json:"min" yaml:"min"`
				Unit string  `json:"unit" yaml:"unit"`
			} `json:"bandwidth" yaml:"bandwidth"`
		} `json:"filters" yaml:"filters"`
		Rotation struct {
			Enable   bool          `json:"enable" yaml:"enable"`
			Interval time.Duration `json:"interval" yaml:"interval"`
			Strategy string        `json:"strategy" yaml:"strategy"`
			MaxUses  int           `json:"max_uses" yaml:"max_uses"`
		} `json:"rotation" yaml:"rotation"`
		Cache struct {
			Enable bool          `json:"enable" yaml:"enable"`
			Size   int           `json:"size" yaml:"size"`
			TTL    time.Duration `json:"ttl" yaml:"ttl"`
		} `json:"cache" yaml:"cache"`
	} `json:"proxy" yaml:"proxy"`
	Log     LogConfig     `json:"log" yaml:"log"`
	Monitor MonitorConfig `json:"monitor" yaml:"monitor"`
}

// LogConfig 日志配置结构
type LogConfig struct {
	File   string `json:"file" yaml:"file"`
	Level  string `json:"level" yaml:"level"`
	Format string `json:"format" yaml:"format"`
}

// MonitorConfig 监控配置结构
type MonitorConfig struct {
	Enable   bool     `json:"enable" yaml:"enable"`
	Interval duration `json:"interval" yaml:"interval"`
	Metrics  []string `json:"metrics" yaml:"metrics"`
	Alerts   []struct {
		Name      string   `json:"name" yaml:"name"`
		Metric    string   `json:"metric" yaml:"metric"`
		Threshold float64  `json:"threshold" yaml:"threshold"`
		Duration  duration `json:"duration" yaml:"duration"`
		Action    string   `json:"action" yaml:"action"`
	} `json:"alerts" yaml:"alerts"`
}

// duration 自定义持续时间类型
type duration time.Duration

// UnmarshalJSON 实现JSON解析
func (d *duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = duration(tmp)
		return nil
	default:
		return fmt.Errorf("invalid duration")
	}
}

// UnmarshalYAML 实现YAML解析
func (d *duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v interface{}
	if err := unmarshal(&v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = duration(tmp)
		return nil
	default:
		return fmt.Errorf("invalid duration")
	}
}

// LoadConfig 加载配置文件
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file failed: %v", err)
	}

	config := &Config{}
	switch filepath.Ext(filename) {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("parse json config failed: %v", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("parse yaml config failed: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", filepath.Ext(filename))
	}

	return config, nil
}

// SaveConfig 保存配置文件
func SaveConfig(config *Config, filename string) error {
	var data []byte
	var err error

	switch filepath.Ext(filename) {
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal json config failed: %v", err)
		}
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
		if err != nil {
			return fmt.Errorf("marshal yaml config failed: %v", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", filepath.Ext(filename))
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("write config file failed: %v", err)
	}

	return nil
}

// DefaultConfig 创建默认配置
func DefaultConfig() *Config {
	config := &Config{
		Version: "1.0.0",
		Debug:   false,
	}

	// GUI默认配置
	config.GUI.Web.Enable = false
	config.GUI.Web.Port = ":8080"
	config.GUI.Terminal.Enable = true

	// 系统默认配置
	config.System.MaxProcs = runtime.NumCPU()
	config.System.MaxFiles = 1000000
	config.System.CPULimit = 0
	config.System.MemLimit = 0

	// 攻击默认配置
	config.Attack.Method = "GET"
	config.Attack.Duration = time.Minute
	config.Attack.Rate = 50
	config.Attack.Workers = 10
	config.Attack.Timeout = 5 * time.Second
	config.Attack.Mode = "get-flood"
	config.Attack.Headers = make(map[string]string)
	config.Attack.UserAgent.Type = "random"
	config.Attack.UserAgent.CustomFile = ""
	config.Attack.HTTP2 = false
	config.Attack.KeepAlive = false
	config.Attack.FollowRedirect = false
	config.Attack.WSFrameSize = 1024
	config.Attack.WSCompression = false

	// 代理默认配置
	config.Proxy.Enable = false
	config.Proxy.Type = "none"
	config.Proxy.Settings = struct {
		Timeout         time.Duration `json:"timeout" yaml:"timeout"`
		Interval        time.Duration `json:"interval" yaml:"interval"`
		MaxFails        int           `json:"max_fails" yaml:"max_fails"`
		RetryTimes      int           `json:"retry_times" yaml:"retry_times"`
		Failover        bool          `json:"failover" yaml:"failover"`
		ValidateEnable  bool          `json:"validate_enable" yaml:"validate_enable"`
		ValidateURL     string        `json:"validate_url" yaml:"validate_url"`
		ValidateTimeout time.Duration `json:"validate_timeout" yaml:"validate_timeout"`
		MaxConns        int           `json:"max_conns" yaml:"max_conns"`                   // 最大连接总数
		MaxConnsPerHost int           `json:"max_conns_per_host" yaml:"max_conns_per_host"` // 每个主机的最大连接数
	}{
		Timeout:         3 * time.Second,
		Interval:        time.Minute,
		MaxFails:        5,
		RetryTimes:      3,
		Failover:        true,
		ValidateEnable:  true,
		ValidateURL:     "http://www.baidu.com",
		MaxConns:        100, // 默认最大连接总数为100
		MaxConnsPerHost: 100, // 默认每个主机的最大连接数为100
	}

	// 绕过默认配置
	config.Bypass.RandomizeUA = true
	config.Bypass.DelayMin = 100 * time.Millisecond
	config.Bypass.DelayMax = time.Second
	config.Bypass.RetryCount = 3
	config.Bypass.RetryInterval = time.Second
	config.Bypass.CustomHeaders = make(map[string]string)

	// 日志默认配置
	config.Log.Level = "info"
	config.Log.Format = "text"

	// 监控默认配置
	config.Monitor.Enable = true
	config.Monitor.Interval = duration(time.Second)
	config.Monitor.Metrics = []string{
		"requests",
		"latency",
		"success_rate",
		"error_rate",
		"proxy_health",
	}

	return config
}

// LoadAttackConfig 加载攻击配置文件
func LoadAttackConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read attack config file failed: %v", err)
	}

	config := &Config{}
	switch filepath.Ext(filename) {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("parse json attack config failed: %v", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("parse yaml attack config failed: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", filepath.Ext(filename))
	}

	return config, nil
}

// LoadProxyConfig loads and parses the api_proxy.yaml file
func LoadProxyConfig(filePath string) (*ProxyConfig, error) {
	log.Printf("[DEBUG] Attempting to open config file: %s\n", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[ERROR] Failed to open config file: %v\n", err)
		return nil, err
	}
	defer file.Close()

	log.Printf("[DEBUG] Reading config file: %s\n", filePath)
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("[ERROR] Failed to read config file: %v\n", err)
		return nil, err
	}

	log.Printf("[DEBUG] Unmarshalling config data\n")
	var config ProxyConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshal config data: %v\n", err)
		return nil, err
	}

	log.Printf("[DEBUG] Loaded proxy config: %+v\n", config)

	return &config, nil
}
