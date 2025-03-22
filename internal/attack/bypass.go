package attack

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// NewBypassManager creates a new bypass manager
func NewBypassManager(methodNames []string) *BypassManager {
	config := &BypassConfig{
		Methods: make([]BypassMethod, len(methodNames)),
	}

	for i, m := range methodNames {
		config.Methods[i] = BypassMethod(m)
	}

	manager := &BypassManager{
		config:  config,
		methods: make(map[BypassMethod]BypassMethodHandler),
	}
	manager.registerMethods()
	return manager
}

// GetMethods returns all bypass methods
func (b *BypassManager) GetMethods() []BypassMethod {
	return b.config.Methods
}

// Apply applies all configured bypass methods to the request
func (b *BypassManager) Apply(req *http.Request) error {
	for _, method := range b.config.Methods {
		if handler, ok := b.methods[method]; ok {
			if err := handler.Apply(req); err != nil {
				return fmt.Errorf("bypass method %s failed: %v", method, err)
			}
		}
	}
	return nil
}

// ValidateBypassMethods validates bypass methods for the specified attack method
func ValidateBypassMethods(attackMethod Method, methods []BypassMethod) ([]BypassMethod, []BypassMethod) {
	validMethods := make([]BypassMethod, 0)
	invalidMethods := make([]BypassMethod, 0)

	for _, method := range methods {
		if ProtocolBypassMethods[attackMethod][method] {
			validMethods = append(validMethods, method)
		} else {
			invalidMethods = append(invalidMethods, method)
		}
	}

	return validMethods, invalidMethods
}

// Concrete bypass method implementations

// TLSBypassHandler implements TLS bypass
type TLSBypassHandler struct {
	config *tls.Config
}

func (t *TLSBypassHandler) Apply(req *http.Request) error {
	// TLS bypass implementation
	return nil
}

// HeaderBypassHandler implements header bypass
type HeaderBypassHandler struct {
	customHeaders map[string]string
}

func (h *HeaderBypassHandler) Apply(req *http.Request) error {
	for k, v := range h.customHeaders {
		req.Header.Set(k, v)
	}
	return nil
}

// PathBypassHandler implements path-based bypass
type PathBypassHandler struct{}

func (p *PathBypassHandler) Apply(req *http.Request) error {
	path := req.URL.Path
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	path += fmt.Sprintf("?_=%d", time.Now().UnixNano())
	req.URL.Path = path
	return nil
}

// RateLimitBypassHandler implements rate limiting bypass
type RateLimitBypassHandler struct {
	delayMin time.Duration
	delayMax time.Duration
}

func (r *RateLimitBypassHandler) Apply(req *http.Request) error {
	if r.delayMax > 0 {
		delay := time.Duration(rand.Int63n(int64(r.delayMax-r.delayMin))) + r.delayMin
		time.Sleep(delay)
	}
	return nil
}

// CompressionBypassHandler implements compression bypass
type CompressionBypassHandler struct{}

func (c *CompressionBypassHandler) Apply(req *http.Request) error {
	req.Header.Set("Accept-Encoding", "identity")
	return nil
}

// CharsetBypassHandler implements charset bypass
type CharsetBypassHandler struct{}

func (c *CharsetBypassHandler) Apply(req *http.Request) error {
	req.Header.Set("Accept-Charset", "utf-8;q=0.7,*;q=0.7")
	return nil
}

// BehaviorBypassHandler implements behavior bypass
type BehaviorBypassHandler struct{}

func (b *BehaviorBypassHandler) Apply(req *http.Request) error {
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("DNT", "1")
	return nil
}

// UASpoofHandler implements User-Agent spoofing bypass
type UASpoofHandler struct {
	userAgents []string
}

func (u *UASpoofHandler) Apply(req *http.Request) error {
	if len(u.userAgents) > 0 {
		ua := u.userAgents[rand.Intn(len(u.userAgents))]
		req.Header.Set("User-Agent", ua)
	}
	return nil
}

// IPRotateHandler implements IP rotation bypass
type IPRotateHandler struct{}

func (i *IPRotateHandler) Apply(req *http.Request) error {
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)))
	return nil
}

// ProxyChainHandler implements proxy chain bypass
type ProxyChainHandler struct {
	chain []string
}

func (p *ProxyChainHandler) Apply(req *http.Request) error {
	// Proxy chain logic is implemented in proxy layer
	return nil
}

// HeaderModHandler implements header modification bypass
type HeaderModHandler struct {
	headers map[string]string
}

func (h *HeaderModHandler) Apply(req *http.Request) error {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return nil
}

// registerMethods registers all bypass methods
func (b *BypassManager) registerMethods() {
	b.methods[TLSBypass] = &TLSBypassHandler{config: b.config.TLSConfig}
	b.methods[HeaderBypass] = &HeaderBypassHandler{customHeaders: b.config.CustomHeaders}
	b.methods[PathBypass] = &PathBypassHandler{}
	b.methods[RateLimitBypass] = &RateLimitBypassHandler{
		delayMin: b.config.DelayMin,
		delayMax: b.config.DelayMax,
	}
	b.methods[CompressionBypass] = &CompressionBypassHandler{}
	b.methods[CharsetBypass] = &CharsetBypassHandler{}
	b.methods[BehaviorBypass] = &BehaviorBypassHandler{}
	b.methods[UASpoof] = &UASpoofHandler{userAgents: b.config.UserAgents}
	b.methods[IPRotate] = &IPRotateHandler{}
	b.methods[ProxyChain] = &ProxyChainHandler{chain: b.config.ProxyChain}
	b.methods[HeaderMod] = &HeaderModHandler{headers: b.config.CustomHeaders}
}
