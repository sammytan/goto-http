package attack

import (
	"context"
	"sync"
	"time"

	"goto-http/internal/proxy"
	"goto-http/internal/useragent"
	httplib "goto-http/pkg/protocol/http"
	"goto-http/pkg/protocol/websocket"
	"goto-http/pkg/random"
)

// Attacker defines the attack interface
type Attacker interface {
	Attack(ctx context.Context) error
	Stop()
	Stats() *Stats
}

// AttackMethod defines the attack method interface
type AttackMethod interface {
	Name() string
	Description() string
	Execute(ctx context.Context, opts *Options) error
	Validate(opts *Options) error
}

// AttackStats defines the statistics interface
type AttackStats interface {
	Total() uint64
	Success() uint64
	Failed() uint64
	Duration() time.Duration
	Rate() float64
	Latency() *LatencyStats
}

// BaseAttacker 基础攻击实现
type BaseAttacker struct {
	ctx     context.Context
	cancel  context.CancelFunc
	clients *AttackClients
	stats   *Stats
	options *Options
}

// NewBaseAttacker 创建基础攻击实例
func NewBaseAttacker(opts *Options) *BaseAttacker {
	ctx, cancel := context.WithCancel(context.Background())
	return &BaseAttacker{
		ctx:    ctx,
		cancel: cancel,
		stats: &Stats{
			Start:  time.Now(),
			Codes:  make(map[int]int64),
			Errors: make(map[string]int),
			Mu:     sync.RWMutex{},
		},
		options: opts,
	}
}

// Init 初始化攻击实例
func (b *BaseAttacker) Init(ctx context.Context) error {
	// 初始化HTTP客户端
	httpClient, err := httplib.NewClient(*b.options.HTTPOptions)
	if err != nil {
		return err
	}

	// 初始化WebSocket客户端
	wsClient := websocket.NewClient(*b.options.WSOptions)

	// 初始化代理管理器
	proxyConfig := &proxy.Config{
		ValidateURL: b.options.ProxyOptions.ValidateURL,
	}
	proxyManager, err := proxy.NewManager(proxyConfig)
	if err != nil {
		return err
	}

	// 初始化绕过管理器
	bypassManager := NewBypassManager(b.options.BypassMethods)

	// 初始化UA管理器
	uaManager, err := useragent.NewManager(useragent.RANDOM, "")
	if err != nil {
		return err
	}

	// 初始化随机生成器
	randGen := random.NewGenerator()

	// 设置客户端集合
	b.clients = &AttackClients{
		HTTP:      httpClient,
		WebSocket: wsClient,
		Proxy:     proxyManager,
		Bypass:    bypassManager,
		UA:        uaManager,
		Random:    randGen,
	}

	return nil
}

// Stop 停止攻击
func (b *BaseAttacker) Stop() error {
	if b.cancel != nil {
		b.cancel()
	}

	// 关闭所有客户端
	if b.clients != nil {
		if b.clients.HTTP != nil {
			b.clients.HTTP.Close()
		}
		if b.clients.WebSocket != nil {
			b.clients.WebSocket.Close()
		}
		if b.clients.Proxy != nil {
			b.clients.Proxy.Close()
		}
	}

	return nil
}

// GetStats 获取统计信息
func (b *BaseAttacker) GetStats() *Stats {
	return b.stats
}

// GetRawStats 获取原始统计信息结构体（与GetStats相同，用于兼容性）
func (b *BaseAttacker) GetRawStats() *Stats {
	return b.stats
}
