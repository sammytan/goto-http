package proxy

import (
	"fmt"
	"net/http"
	"time"
)

// Option 代理管理器选项配置函数
type Option func(*Manager) error

// WithMaxFails 设置最大失败次数
func WithMaxFails(n int) func(*Manager) error {
	return func(m *Manager) error {
		if n < 0 {
			return fmt.Errorf("max failures must be greater than or equal to 0")
		}
		m.maxFails = n
		return nil
	}
}

// WithRetryInterval 设置重试间隔
func WithRetryInterval(d time.Duration) func(*Manager) error {
	return func(m *Manager) error {
		if d <= 0 {
			return fmt.Errorf("retry interval must be greater than 0")
		}
		m.retryInterval = d
		return nil
	}
}

// WithClient 设置HTTP客户端
func WithClient(client *http.Client) Option {
	return func(m *Manager) error {
		m.client = client
		return nil
	}
}

// WithProxyPool 添加代理池
func WithProxyPool(pool *ProxyPool) Option {
	return func(m *Manager) error {
		if pool == nil {
			return fmt.Errorf("proxy pool cannot be nil")
		}
		if m.pools == nil {
			m.pools = make([]*ProxyPool, 0)
		}
		m.pools = append(m.pools, pool)
		return nil
	}
}

// WithProxyPools 添加多个代理池
func WithProxyPools(pools []*ProxyPool) Option {
	return func(m *Manager) error {
		if len(pools) == 0 {
			return fmt.Errorf("proxy pools cannot be empty")
		}
		if m.pools == nil {
			m.pools = make([]*ProxyPool, 0, len(pools))
		}
		m.pools = append(m.pools, pools...)
		return nil
	}
}

// WithFilterRules 设置过滤规则
func WithFilterRules(rules []FilterRule) Option {
	return func(m *Manager) error {
		for i := range m.pools {
			m.pools[i].FilterRules = append(m.pools[i].FilterRules, rules...)
		}
		return nil
	}
}

// WithProxyType sets the proxy type
func WithProxyType(proxyType ProxyType) Option {
	return func(m *Manager) error {
		switch proxyType {
		case TYPE_NONE, TYPE_FILE, TYPE_API, TYPE_SERVER:
			m.config.Type = proxyType
			return nil
		default:
			return fmt.Errorf("invalid proxy type: %s", proxyType)
		}
	}
}

// WithProxyFile sets the proxy file path
func WithProxyFile(filePath string) Option {
	return func(m *Manager) error {
		if m.config.Type != TYPE_FILE {
			return fmt.Errorf("proxy type must be 'file' to use proxy file")
		}
		m.config.File = filePath
		return nil
	}
}

// WithProxyPoolName sets the proxy pool name
func WithProxyPoolName(poolName string) Option {
	return func(m *Manager) error {
		if m.config.Type != TYPE_API && m.config.Type != TYPE_SERVER {
			return fmt.Errorf("proxy type must be 'api' or 'server' to use proxy pool")
		}
		m.config.APIPool = poolName
		return nil
	}
}
