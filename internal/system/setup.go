package system

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"goto-http/internal/cli"
)

// Setup 设置系统参数
func Setup(config *cli.Config) error {
	// 设置GOMAXPROCS
	if config.MaxProcs > 0 {
		runtime.GOMAXPROCS(config.MaxProcs)
	}

	// 设置最大文件描述符数
	if config.MaxFileDesc > 0 {
		var rLimit syscall.Rlimit
		err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		if err != nil {
			return fmt.Errorf("获取文件描述符限制失败: %v", err)
		}

		rLimit.Cur = config.MaxFileDesc
		if rLimit.Cur > rLimit.Max {
			rLimit.Cur = rLimit.Max
		}

		err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		if err != nil {
			return fmt.Errorf("设置文件描述符限制失败: %v", err)
		}
	}

	// 设置内存限制
	if config.MemLimit > 0 {
		maxMemory := int64(config.MemLimit) * 1024 * 1024 // 转换为字节
		debug.SetMemoryLimit(maxMemory)
	}

	// 设置CPU限制
	if config.CPULimit > 0 {
		var rLimit syscall.Rlimit
		err := syscall.Getrlimit(syscall.RLIMIT_CPU, &rLimit)
		if err != nil {
			return fmt.Errorf("获取CPU限制失败: %v", err)
		}

		rLimit.Cur = uint64(config.CPULimit)
		if rLimit.Cur > rLimit.Max {
			rLimit.Cur = rLimit.Max
		}

		err = syscall.Setrlimit(syscall.RLIMIT_CPU, &rLimit)
		if err != nil {
			return fmt.Errorf("设置CPU限制失败: %v", err)
		}
	}

	return nil
}

// GetSystemInfo 获取系统信息
func GetSystemInfo() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	hostname, _ := os.Hostname()

	return map[string]interface{}{
		"hostname":   hostname,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]uint64{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"heap_alloc":  m.HeapAlloc,
			"heap_sys":    m.HeapSys,
		},
	}
}

// MonitorResources 监控资源使用
func MonitorResources(stats chan<- map[string]interface{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		stats <- map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"memory": map[string]uint64{
				"alloc":       m.Alloc,
				"total_alloc": m.TotalAlloc,
				"sys":         m.Sys,
				"heap_alloc":  m.HeapAlloc,
				"heap_sys":    m.HeapSys,
			},
		}
	}
}
