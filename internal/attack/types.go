package attack

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"crypto/tls"
	"goto-http/internal/proxy"
	"goto-http/internal/useragent"
	httplib "goto-http/pkg/protocol/http"
	"goto-http/pkg/protocol/websocket"
	"goto-http/pkg/random"
)

// Method defines attack method type
type Method string

const (
	// Basic HTTP attacks
	GET_FLOOD       Method = "get-flood"
	POST_FLOOD      Method = "post-flood"
	HEAD_FLOOD      Method = "head-flood"
	OPTIONS_FLOOD   Method = "options-flood"
	TRACE_FLOOD     Method = "trace-flood"
	MIXED_METHOD    Method = "mixed-method"
	BODY_FLOOD      Method = "body-flood"
	CHUNK_FLOOD     Method = "chunk-flood"
	EXPECT_FLOOD    Method = "expect-flood"
	RANGE_FLOOD     Method = "range-flood"
	MULTIPART_FLOOD Method = "multipart-flood"
	SLOWLORIS       Method = "slowloris"
	SLOWPOST        Method = "slowpost"

	// HTTP/2 attacks
	HTTP2_FLOOD       Method = "http2flood"
	HTTP2_PRIORITY    Method = "http2priority"
	HTTP2_RST         Method = "http2rst"
	HTTP2_GOAWAY      Method = "http2goaway"
	H2_WINDOW_UPDATE  Method = "h2-window-update"
	H2_PING_FLOOD     Method = "h2-ping-flood"
	H2_PUSH_PROMISE   Method = "h2-push-promise"
	H2_STREAM_DEP     Method = "h2-stream-dep"
	H2_SETTINGS_FLOOD Method = "h2-settings-flood"
	H2_HEADER_TABLE   Method = "h2-header-table"

	// WebSocket attacks
	WS_FLOOD           Method = "ws-flood"
	WS_FRAGMENT        Method = "ws-fragment"
	WS_COMPRESS_AMP    Method = "ws-compress-amp"
	WS_PING_FLOOD      Method = "ws-ping-flood"
	WS_FRAME_MASKING   Method = "ws-frame-masking"
	WS_CONN_FLOOD      Method = "ws-connection-flood"
	WS_PROTOCOL_ABUSE  Method = "ws-protocol-abuse"
	WS_EXTENSION_ABUSE Method = "ws-extension-abuse"

	// Protocol confusion attacks
	PROTOCOL_CONFUSION Method = "protocol-confusion"
	UPGRADE_ABUSE      Method = "upgrade-abuse"
	WEBSOCKET_TUNNEL   Method = "websocket-tunnel"
	HTTP_TUNNEL        Method = "http-tunnel"

	// Smart attacks
	SMART_FLOOD      Method = "smart-flood"
	MIXED_PROTOCOL   Method = "mixed-protocol"
	RESOURCE_EXHAUST Method = "resource-exhaust"
	CONNECTION_ABUSE Method = "connection-abuse"

	// Special attacks
	CACHE_POISON      Method = "cache-poison"
	DNS_REBINDING     Method = "dns-rebinding"
	REQUEST_SMUGGLING Method = "request-smuggling"
	PARAM_POLLUTION   Method = "parameter-pollution"
)

// AttackMode defines attack mode
type AttackMode string

const (
	MODE_NORMAL     AttackMode = "normal"     // Normal mode
	MODE_STEALTH    AttackMode = "stealth"    // Stealth mode
	MODE_AGGRESSIVE AttackMode = "aggressive" // Aggressive mode
)

// Stats tracks attack statistics
type Stats struct {
	Total               uint64          `json:"total"`                // Total requests
	Success             uint64          `json:"success"`              // Successful requests
	Failed              uint64          `json:"failed"`               // Failed requests
	Start               time.Time       `json:"start_time"`           // Attack start time
	Duration            time.Duration   `json:"duration"`             // Attack duration
	BytesSent           int64           `json:"bytes_sent"`           // Total bytes sent
	BytesReceived       int64           `json:"bytes_received"`       // Total bytes received
	TotalLatency        int64           `json:"total_latency"`        // Total latency
	MinLatency          int64           `json:"min_latency"`          // Minimum latency
	MaxLatency          int64           `json:"max_latency"`          // Maximum latency
	Codes               map[int]int64   `json:"codes"`                // HTTP status code counts
	Errors              map[string]int  `json:"errors"`               // Error type counts
	LatencyDistribution map[int64]int64 `json:"latency_distribution"` // Latency distribution

	// System metrics
	CPUUsage     float64 `json:"cpu_usage"`     // CPU usage percentage
	MemUsage     float64 `json:"mem_usage"`     // Memory usage percentage
	GCUsage      float64 `json:"gc_usage"`      // Garbage collection usage
	Bandwidth    float64 `json:"bandwidth"`     // Current bandwidth usage
	TotalTraffic float64 `json:"total_traffic"` // Total traffic sent/received

	// Real-time metrics
	RequestRate  float64 `json:"request_rate"`  // Requests per second
	ByteRate     float64 `json:"byte_rate"`     // Bytes per second
	CurrentRPS   float64 `json:"current_rps"`   // Current requests per second
	ResponseTime float64 `json:"response_time"` // Current response time

	// Thread-safety
	Mu sync.RWMutex `json:"-"` // Mutex for thread safety
}

// LatencyStats holds latency statistics
type LatencyStats struct {
	Min      time.Duration // Minimum latency
	Max      time.Duration // Maximum latency
	Average  time.Duration // Average latency
	Variance float64       // Latency variance
}

// AttackClients holds all client instances
type AttackClients struct {
	HTTP      *httplib.Client
	WebSocket *websocket.Client
	Proxy     *proxy.Manager
	Bypass    *BypassManager
	UA        *useragent.Manager
	Random    *random.Generator
}

// UserAgent 定义用户代理配置
type UserAgent struct {
	Type       string `json:"type" yaml:"type"`               // 用户代理类型: random, custom
	CustomFile string `json:"custom_file" yaml:"custom_file"` // 自定义用户代理文件
}

// String returns a string representation of the Stats
func (s *Stats) String() string {
	s.Mu.RLock()
	defer s.Mu.RUnlock()

	avgLatency := int64(0)
	if s.Total > 0 {
		avgLatency = s.TotalLatency / int64(s.Total)
	}

	stats := fmt.Sprintf(
		"\nAttack Stats:\n"+
			"  Total Requests: %d\n"+
			"  Success Rate: %.2f%%\n"+
			"  Average Latency: %dms\n"+
			"  Min Latency: %dms\n"+
			"  Max Latency: %dms\n"+
			"  Bytes Sent: %d\n"+
			"  Bytes Received: %d\n"+
			"  Request Rate: %.2f req/s\n"+
			"  Transfer Rate: %.2f KB/s\n\n"+
			"Latency Distribution:\n"+
			"  0-100ms: %d requests\n"+
			"  100-200ms: %d requests\n"+
			"  200-500ms: %d requests\n"+
			"  500ms-1s: %d requests\n"+
			"  >1s: %d requests\n\n"+
			"Status Code Distribution:\n",
		s.Total,
		float64(s.Success)/float64(s.Total)*100,
		avgLatency,
		s.MinLatency,
		s.MaxLatency,
		s.BytesSent,
		s.BytesReceived,
		s.RequestRate,
		s.ByteRate/1024,
		s.LatencyDistribution[100],
		s.LatencyDistribution[200],
		s.LatencyDistribution[500],
		s.LatencyDistribution[1000],
		s.LatencyDistribution[9999],
	)

	// Add status code distribution
	var codes []int
	for code := range s.Codes {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	for _, code := range codes {
		stats += fmt.Sprintf("  %d: %d requests\n", code, s.Codes[code])
	}

	// Add error distribution if any
	if len(s.Errors) > 0 {
		stats += "\nError Distribution:\n"
		for errType, count := range s.Errors {
			stats += fmt.Sprintf("  %s: %d\n", errType, count)
		}
	}

	return stats
}

// BypassMethod defines bypass method type
type BypassMethod string

const (
	// HTTP bypass methods
	TLSBypass         BypassMethod = "tls_bypass"         // TLS bypass
	BehaviorBypass    BypassMethod = "behavior_bypass"    // Behavior bypass
	HeaderBypass      BypassMethod = "header_bypass"      // Header bypass
	PathBypass        BypassMethod = "path_bypass"        // Path bypass
	RateLimitBypass   BypassMethod = "rate_limit_bypass"  // Rate limit bypass
	CompressionBypass BypassMethod = "compression_bypass" // Compression bypass
	CharsetBypass     BypassMethod = "charset_bypass"     // Charset bypass

	// WebSocket bypass methods
	WSFragmentBypass  BypassMethod = "ws_fragment_bypass"  // WebSocket fragment bypass
	WSProtocolBypass  BypassMethod = "ws_protocol_bypass"  // WebSocket protocol bypass
	WSExtensionBypass BypassMethod = "ws_extension_bypass" // WebSocket extension bypass
	WSFrameBypass     BypassMethod = "ws_frame_bypass"     // WebSocket frame bypass

	// Common bypass methods
	UASpoof    BypassMethod = "ua_spoof"    // User-Agent spoofing
	IPRotate   BypassMethod = "ip_rotate"   // IP rotation
	ProxyChain BypassMethod = "proxy_chain" // Proxy chain
	HeaderMod  BypassMethod = "header_mod"  // Header modification
)

// BypassMethodHandler defines the interface for bypass methods
type BypassMethodHandler interface {
	Apply(req *http.Request) error
}

// BypassManager manages bypass methods
type BypassManager struct {
	config  *BypassConfig
	methods map[BypassMethod]BypassMethodHandler
}

// BypassConfig defines bypass configuration
type BypassConfig struct {
	Methods       []BypassMethod    // Enabled bypass methods
	CustomHeaders map[string]string // Custom headers
	TLSConfig     *tls.Config       // TLS configuration
	ProxyURL      string            // Proxy URL
	RandomizeUA   bool              // Randomize User-Agent
	DelayMin      time.Duration     // Minimum delay
	DelayMax      time.Duration     // Maximum delay
	RetryCount    int               // Retry count
	RetryInterval time.Duration     // Retry interval
	CustomRules   map[string]string // Custom rules
	UserAgents    []string          // User-Agent list
	ProxyChain    []string          // Proxy chain
}

// ProtocolBypassMethods maps protocols to their supported bypass methods
var ProtocolBypassMethods = map[Method]map[BypassMethod]bool{
	GET_FLOOD: {
		TLSBypass:         true,
		BehaviorBypass:    true,
		HeaderBypass:      true,
		PathBypass:        true,
		RateLimitBypass:   true,
		CompressionBypass: true,
		CharsetBypass:     true,
		UASpoof:           true,
		IPRotate:          true,
		ProxyChain:        true,
		HeaderMod:         true,
	},
	POST_FLOOD: {
		TLSBypass:         true,
		BehaviorBypass:    true,
		HeaderBypass:      true,
		PathBypass:        true,
		RateLimitBypass:   true,
		CompressionBypass: true,
		CharsetBypass:     true,
		UASpoof:           true,
		IPRotate:          true,
		ProxyChain:        true,
		HeaderMod:         true,
	},
	// Add other HTTP methods...

	// WebSocket methods
	WS_FLOOD: {
		TLSBypass:         true,
		WSFragmentBypass:  true,
		WSProtocolBypass:  true,
		WSExtensionBypass: true,
		WSFrameBypass:     true,
		UASpoof:           true,
		IPRotate:          true,
		ProxyChain:        true,
		HeaderMod:         true,
	},
	WS_FRAGMENT: {
		TLSBypass:         true,
		WSFragmentBypass:  true,
		WSProtocolBypass:  true,
		WSExtensionBypass: true,
		WSFrameBypass:     true,
		UASpoof:           true,
		IPRotate:          true,
		ProxyChain:        true,
		HeaderMod:         true,
	},
	// Add other WebSocket methods...
}
