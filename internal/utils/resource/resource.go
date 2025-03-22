package resource

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// ResourceLimits 资源限制配置
type ResourceLimits struct {
	CPUPercentage    int
	MemoryPercentage int
	MaxFiles         int
	MaxConns         int
}

// ResourceMonitor 资源监控器
type ResourceMonitor struct {
	limits      ResourceLimits
	stopChan    chan struct{}
	metricsChan chan ResourceMetrics
}

// ResourceMetrics 资源使用指标
type ResourceMetrics struct {
	CPUUsage    float64
	MemoryUsage float64
	OpenFiles   int64
	Connections int64
	Timestamp   time.Time
}

// NewResourceMonitor 创建资源监控器
func NewResourceMonitor(limits ResourceLimits) *ResourceMonitor {
	return &ResourceMonitor{
		limits:      limits,
		stopChan:    make(chan struct{}),
		metricsChan: make(chan ResourceMetrics, 100),
	}
}

// Start 启动资源监控
func (rm *ResourceMonitor) Start() error {
	// 设置系统资源限制
	if err := rm.setSystemLimits(); err != nil {
		return err
	}

	// 启动监控协程
	go rm.monitor()

	return nil
}

// Stop 停止资源监控
func (rm *ResourceMonitor) Stop() {
	close(rm.stopChan)
}

// GetMetrics 获取资源指标通道
func (rm *ResourceMonitor) GetMetrics() <-chan ResourceMetrics {
	return rm.metricsChan
}

// setSystemLimits 设置系统资源限制
func (rm *ResourceMonitor) setSystemLimits() error {
	var rLimit syscall.Rlimit
	rLimit.Max = uint64(rm.limits.MaxFiles)
	rLimit.Cur = uint64(rm.limits.MaxFiles)

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return fmt.Errorf("failed to set file limit: %v", err)
	}

	// 设置GOMAXPROCS
	runtime.GOMAXPROCS(runtime.NumCPU())

	return nil
}

// monitor 监控资源使用情况
func (rm *ResourceMonitor) monitor() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopChan:
			return
		case <-ticker.C:
			metrics, err := rm.collectMetrics()
			if err != nil {
				continue
			}

			// 检查资源限制
			if rm.checkLimits(metrics) {
				rm.metricsChan <- metrics
			}
		}
	}
}

// collectMetrics 收集资源使用指标
func (rm *ResourceMonitor) collectMetrics() (ResourceMetrics, error) {
	metrics := ResourceMetrics{
		Timestamp: time.Now(),
	}

	// 获取CPU使用率
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		metrics.CPUUsage = cpuPercent[0]
	}

	// 获取内存使用率
	memInfo, err := mem.VirtualMemory()
	if err == nil {
		metrics.MemoryUsage = memInfo.UsedPercent
	}

	// 获取打开文件数
	if pid := os.Getpid(); pid > 0 {
		if _, err := os.FindProcess(pid); err == nil {
			// TODO: 实现获取进程打开文件数的逻辑
			metrics.OpenFiles = 0
		}
	}

	// 获取连接数
	// TODO: 实现获取当前连接数的逻辑
	metrics.Connections = 0

	return metrics, nil
}

// checkLimits 检查资源限制
func (rm *ResourceMonitor) checkLimits(metrics ResourceMetrics) bool {
	if metrics.CPUUsage > float64(rm.limits.CPUPercentage) {
		return false
	}

	if metrics.MemoryUsage > float64(rm.limits.MemoryPercentage) {
		return false
	}

	if metrics.OpenFiles > int64(rm.limits.MaxFiles) {
		return false
	}

	if metrics.Connections > int64(rm.limits.MaxConns) {
		return false
	}

	return true
}

// AdjustResources 动态调整资源使用
func (rm *ResourceMonitor) AdjustResources(metrics ResourceMetrics) {
	// TODO: 实现动态资源调整逻辑
	// 1. 根据CPU使用率调整并发数
	// 2. 根据内存使用率调整缓冲区大小
	// 3. 根据文件句柄使用情况调整连接池
}

// GetSystemInfo 获取系统信息
func GetSystemInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["cpu_cores"] = runtime.NumCPU()
	info["go_version"] = runtime.Version()
	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH

	if memInfo, err := mem.VirtualMemory(); err == nil {
		info["total_memory"] = memInfo.Total
		info["available_memory"] = memInfo.Available
	}

	return info
}
