package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Validator 代理验证器
type Validator struct {
	URL     string
	Timeout time.Duration
	Client  *http.Client
}

// Validate validates a proxy by making a test request
func (v *Validator) Validate(proxy *Proxy) error {
	if v.URL == "" {
		return fmt.Errorf("validation URL is required")
	}

	proxyURL, err := proxy.ToURL()
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: v.Timeout,
	}

	req, err := http.NewRequest("GET", v.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// ToURL converts a proxy to a URL
func (p *Proxy) ToURL() (*url.URL, error) {
	if p.URL == "" {
		return nil, fmt.Errorf("proxy URL is required")
	}
	return url.Parse(p.URL)
}

// ValidateProxy 验证单个代理
func (v *Validator) ValidateProxy(proxy string) error {
	if v.URL == "" {
		return fmt.Errorf("validation URL is required")
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: v.Timeout,
	}

	req, err := http.NewRequest("GET", v.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// ValidateProxies 验证代理列表
func (v *Validator) ValidateProxies(proxies []string) ([]string, error) {
	var validProxies []string
	for _, proxy := range proxies {
		if err := v.ValidateProxy(proxy); err == nil {
			validProxies = append(validProxies, proxy)
		}
	}
	return validProxies, nil
}
