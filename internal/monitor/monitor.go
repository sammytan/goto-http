package monitor

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// MetricType 指标类型
type MetricType string

const (
	REQUEST_COUNT MetricType = "request_count"
	SUCCESS_RATE  MetricType = "success_rate"
	LATENCY       MetricType = "latency"
	ERROR_RATE    MetricType = "error_rate"
	PROXY_HEALTH  MetricType = "proxy_health"
	BYPASS_STATUS MetricType = "bypass_status"
)

// Metric 监控指标
type Metric struct {
	Type      MetricType
	Value     float64
	Timestamp time.Time
	Labels    map[string]string
}

// Alert 告警配置
type Alert struct {
	MetricType MetricType
	Threshold  float64
	Operator   string // >, <, >=, <=, ==
	Duration   time.Duration
	Callback   func(Alert, Metric)
}

// Monitor 监控系统
type Monitor struct {
	mu       sync.RWMutex
	metrics  map[MetricType][]Metric
	alerts   map[MetricType][]Alert
	ctx      context.Context
	cancel   context.CancelFunc
	interval time.Duration
}

// NewMonitor 创建新的监控系统
func NewMonitor(ctx context.Context, interval time.Duration) *Monitor {
	ctx, cancel := context.WithCancel(ctx)
	return &Monitor{
		metrics:  make(map[MetricType][]Metric),
		alerts:   make(map[MetricType][]Alert),
		ctx:      ctx,
		cancel:   cancel,
		interval: interval,
	}
}

// AddMetric 添加监控指标
func (m *Monitor) AddMetric(metric Metric) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.metrics[metric.Type]; !ok {
		m.metrics[metric.Type] = make([]Metric, 0)
	}
	m.metrics[metric.Type] = append(m.metrics[metric.Type], metric)
}

// AddAlert 添加告警规则
func (m *Monitor) AddAlert(alert Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.alerts[alert.MetricType]; !ok {
		m.alerts[alert.MetricType] = make([]Alert, 0)
	}
	m.alerts[alert.MetricType] = append(m.alerts[alert.MetricType], alert)
}

// Start 启动监控
func (m *Monitor) Start() {
	ticker := time.NewTicker(m.interval)
	go func() {
		for {
			select {
			case <-m.ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				m.check()
			}
		}
	}()
}

// check 检查指标和告警
func (m *Monitor) check() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for metricType, metrics := range m.metrics {
		if len(metrics) == 0 {
			continue
		}

		// 获取最新的指标
		latest := metrics[len(metrics)-1]

		// 检查告警规则
		if alerts, ok := m.alerts[metricType]; ok {
			for _, alert := range alerts {
				if m.shouldAlert(alert, latest) {
					alert.Callback(alert, latest)
				}
			}
		}
	}
}

// shouldAlert 判断是否应该告警
func (m *Monitor) shouldAlert(alert Alert, metric Metric) bool {
	switch alert.Operator {
	case ">":
		return metric.Value > alert.Threshold
	case "<":
		return metric.Value < alert.Threshold
	case ">=":
		return metric.Value >= alert.Threshold
	case "<=":
		return metric.Value <= alert.Threshold
	case "==":
		return metric.Value == alert.Threshold
	default:
		return false
	}
}

// GetMetrics 获取指标数据
func (m *Monitor) GetMetrics(metricType MetricType, duration time.Duration) []Metric {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if metrics, ok := m.metrics[metricType]; ok {
		cutoff := time.Now().Add(-duration)
		result := make([]Metric, 0)
		for _, metric := range metrics {
			if metric.Timestamp.After(cutoff) {
				result = append(result, metric)
			}
		}
		return result
	}
	return nil
}

// GetStats 获取统计信息
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]interface{})
	for metricType, metrics := range m.metrics {
		if len(metrics) == 0 {
			continue
		}

		// 计算平均值
		var sum float64
		for _, metric := range metrics {
			sum += metric.Value
		}
		avg := sum / float64(len(metrics))

		stats[string(metricType)] = map[string]interface{}{
			"current": metrics[len(metrics)-1].Value,
			"average": avg,
			"count":   len(metrics),
		}
	}
	return stats
}

// Export 导出监控数据
func (m *Monitor) Export() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data := struct {
		Metrics map[MetricType][]Metric `json:"metrics"`
		Alerts  map[MetricType][]Alert  `json:"alerts"`
	}{
		Metrics: m.metrics,
		Alerts:  m.alerts,
	}

	return json.Marshal(data)
}

// Stop 停止监控
func (m *Monitor) Stop() {
	m.cancel()
}

// Clear 清除监控数据
func (m *Monitor) Clear(metricType MetricType) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if metricType == "" {
		// 清除所有数据
		m.metrics = make(map[MetricType][]Metric)
	} else {
		// 清除指定类型的数据
		delete(m.metrics, metricType)
	}
}

// SetInterval 设置监控间隔
func (m *Monitor) SetInterval(interval time.Duration) {
	m.interval = interval
}
