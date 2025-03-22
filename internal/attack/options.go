package attack

import (
	"fmt"
	"goto-http/internal/proxy"
	"goto-http/internal/useragent"
	httplib "goto-http/pkg/protocol/http"
	"goto-http/pkg/protocol/websocket"
	"net/http"
	"net/url"
	"time"
)

// Options defines attack options
type Options struct {
	Target         string
	Method         string
	Duration       time.Duration
	Rate           int
	Workers        int
	Timeout        time.Duration
	Mode           string
	HTTP2          bool
	FollowRedirect bool
	KeepAlive      bool
	WSCompression  bool
	WSFrameSize    int
	ProxyType      string
	ProxyFile      string
	Debug          bool
	NoLogging      bool // 是否禁用日志输出到控制台
	ProxyOptions   *proxy.Config
	Headers        map[string][]string
	Cookies        []*http.Cookie
	Body           string
	UserAgent      *useragent.Config
	RawTarget      string
	RawHeaders     map[string][]string
	RawCookies     []*http.Cookie
	RawBody        string

	// HTTP client options
	HTTPOptions *httplib.ClientOptions
	WSOptions   *websocket.ClientOptions

	// Bypass configuration
	BypassMethods []string
	BypassConfig  *BypassConfig
}

// Validate validates attack options
func (o *Options) Validate() error {
	if o.Target == "" {
		return fmt.Errorf("target URL is required")
	}
	if _, err := url.Parse(o.Target); err != nil {
		return fmt.Errorf("invalid target URL: %v", err)
	}
	if o.Workers <= 0 {
		return fmt.Errorf("workers must be greater than 0")
	}
	if o.Duration <= 0 {
		return fmt.Errorf("duration must be greater than 0")
	}

	// Validate bypass methods if specified
	if len(o.BypassMethods) > 0 {
		// Convert string methods to BypassMethod type
		methods := make([]BypassMethod, len(o.BypassMethods))
		for i, m := range o.BypassMethods {
			methods[i] = BypassMethod(m)
		}

		// Validate against attack method
		validMethods, invalidMethods := ValidateBypassMethods(Method(o.Method), methods)
		if len(invalidMethods) > 0 {
			return fmt.Errorf("invalid bypass methods for %s attack: %v", o.Method, invalidMethods)
		}

		// Update bypass methods to only valid ones
		o.BypassMethods = make([]string, len(validMethods))
		for i, m := range validMethods {
			o.BypassMethods[i] = string(m)
		}
	}

	return nil
}

// ... existing code ...
