package cli

import (
	"flag"
	"runtime"
)

// Config 系统配置
type Config struct {
	// GUI配置
	WebGui  bool
	TermGui bool
	WebPort string

	// 系统配置
	MaxProcs    int
	MaxFileDesc uint64
	CPULimit    int
	MemLimit    uint64

	// 攻击配置
	Target       string
	Method       string
	Duration     int
	Rate         int
	Workers      int
	Timeout      int
	ProxyFile    string
	ProxyAPI     string
	ProxyTimeout int

	// 日志配置
	LogFile  string
	LogLevel string
}

// ParseFlags 解析命令行参数
func ParseFlags() *Config {
	config := &Config{}

	// GUI配置
	flag.BoolVar(&config.WebGui, "webgui", false, "启用Web界面")
	flag.BoolVar(&config.TermGui, "termgui", true, "启用终端界面")
	flag.StringVar(&config.WebPort, "webport", ":8080", "Web界面端口")

	// 系统配置
	flag.IntVar(&config.MaxProcs, "maxprocs", runtime.NumCPU(), "最大处理器数量")
	flag.Uint64Var(&config.MaxFileDesc, "maxfiles", 1000000, "最大文件描述符数量")
	flag.IntVar(&config.CPULimit, "cpulimit", 0, "CPU使用限制(百分比，0表示不限制)")
	flag.Uint64Var(&config.MemLimit, "memlimit", 0, "内存使用限制(MB，0表示不限制)")

	// 攻击配置
	flag.StringVar(&config.Target, "target", "", "目标URL")
	flag.StringVar(&config.Method, "method", "GET", "请求方法(GET/POST/HEAD等)")
	flag.IntVar(&config.Duration, "duration", 60, "攻击持续时间(秒)")
	flag.IntVar(&config.Rate, "rate", 50, "总体请求速率(每秒总请求数)")
	flag.IntVar(&config.Workers, "workers", 10, "并发工作者数量(同时工作的协程数)")
	flag.IntVar(&config.Timeout, "timeout", 5000, "请求超时时间(毫秒)")
	flag.StringVar(&config.ProxyFile, "proxy-file", "", "代理列表文件")
	flag.StringVar(&config.ProxyAPI, "proxy-api", "", "代理API地址")
	flag.IntVar(&config.ProxyTimeout, "proxy-timeout", 3000, "代理超时时间(毫秒)")

	// 日志配置
	flag.StringVar(&config.LogFile, "logfile", "", "日志文件路径")
	flag.StringVar(&config.LogLevel, "loglevel", "info", "日志级别(debug/info/warn/error)")

	flag.Parse()

	// 如果两个GUI参数都未指定，默认使用termgui
	if flag.Lookup("webgui").Value.String() != "true" && flag.Lookup("termgui").Value.String() != "true" {
		config.TermGui = true
		config.WebGui = false
	}

	return config
}
