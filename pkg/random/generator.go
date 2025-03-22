package random

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"
)

var (
	// 字符集
	digits       = "0123456789"
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// 预定义的UA列表
	userAgents []string
	uaMutex    sync.RWMutex
)

// Generator 随机生成器
type Generator struct {
	// 配置选项
	minInt      int64
	maxInt      int64
	defaultLen  int
	charsets    map[string]string
	customChars string
}

// NewGenerator 创建随机生成器
func NewGenerator() *Generator {
	return &Generator{
		minInt:     0,
		maxInt:     999999,
		defaultLen: 8,
		charsets: map[string]string{
			"digit":   digits,
			"lower":   lowerChars,
			"upper":   upperChars,
			"special": specialChars,
			"all":     digits + lowerChars + upperChars,
		},
	}
}

// SetRange 设置整数范围
func (g *Generator) SetRange(min, max int64) {
	g.minInt = min
	g.maxInt = max
}

// SetDefaultLength 设置默认长度
func (g *Generator) SetDefaultLength(length int) {
	g.defaultLen = length
}

// AddCharset 添加自定义字符集
func (g *Generator) AddCharset(name, chars string) {
	g.charsets[name] = chars
}

// SetCustomChars 设置自定义字符
func (g *Generator) SetCustomChars(chars string) {
	g.customChars = chars
}

// Int 生成随机整数
func (g *Generator) Int() (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(g.maxInt-g.minInt+1))
	if err != nil {
		return 0, err
	}
	return n.Int64() + g.minInt, nil
}

// IntRange 生成指定范围内的随机整数
func (g *Generator) IntRange(min, max int64) (int64, error) {
	if min >= max {
		return 0, fmt.Errorf("min must be less than max")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return 0, err
	}
	return n.Int64() + min, nil
}

// String 生成随机字符串
func (g *Generator) String(length int, charset string) (string, error) {
	if length <= 0 {
		length = g.defaultLen
	}

	chars := g.charsets["all"]
	if charset != "" {
		if cs, ok := g.charsets[charset]; ok {
			chars = cs
		} else {
			chars = charset
		}
	}

	if chars == "" {
		return "", fmt.Errorf("empty charset")
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		result[i] = chars[n.Int64()]
	}
	return string(result), nil
}

// UUID 生成UUID
func (g *Generator) UUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// Email 生成随机邮箱
func (g *Generator) Email() (string, error) {
	domains := []string{"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
	username, err := g.String(8, "lower")
	if err != nil {
		return "", err
	}
	domain := domains[time.Now().UnixNano()%int64(len(domains))]
	return fmt.Sprintf("%s@%s", username, domain), nil
}

// Phone 生成随机手机号
func (g *Generator) Phone() (string, error) {
	prefixes := []string{"130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
		"150", "151", "152", "153", "155", "156", "157", "158", "159",
		"180", "181", "182", "183", "184", "185", "186", "187", "188", "189"}

	prefix := prefixes[time.Now().UnixNano()%int64(len(prefixes))]
	rest, err := g.String(8, "digit")
	if err != nil {
		return "", err
	}
	return prefix + rest, nil
}

// IPv4 生成随机IPv4地址
func (g *Generator) IPv4() (string, error) {
	ip := make([]string, 4)
	for i := 0; i < 4; i++ {
		n, err := g.IntRange(0, 255)
		if err != nil {
			return "", err
		}
		ip[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(ip, "."), nil
}

// IPv6 生成随机IPv6地址
func (g *Generator) IPv6() (string, error) {
	segments := make([]string, 8)
	for i := 0; i < 8; i++ {
		n, err := g.IntRange(0, 65535)
		if err != nil {
			return "", err
		}
		segments[i] = fmt.Sprintf("%04x", n)
	}
	return strings.Join(segments, ":"), nil
}

// Bytes 生成随机字节序列
func (g *Generator) Bytes(length int) ([]byte, error) {
	if length <= 0 {
		length = g.defaultLen
	}
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Hex 生成随机十六进制字符串
func (g *Generator) Hex(length int) (string, error) {
	bytes, err := g.Bytes((length + 1) / 2)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:length], nil
}

// UserAgent 生成随机User-Agent
func (g *Generator) UserAgent(uaType string) (string, error) {
	uaMutex.RLock()
	defer uaMutex.RUnlock()

	if len(userAgents) == 0 {
		return "", fmt.Errorf("no user agents available")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	if err != nil {
		return "", err
	}

	return userAgents[n.Int64()], nil
}

// LoadUserAgents 加载User-Agent列表
func LoadUserAgents(uas []string) {
	uaMutex.Lock()
	defer uaMutex.Unlock()
	userAgents = uas
}

// Float 生成随机浮点数
func (g *Generator) Float(min, max float64, precision int) (float64, error) {
	if min >= max {
		return 0, fmt.Errorf("min must be less than max")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(math.Pow10(precision))))
	if err != nil {
		return 0, err
	}

	f := min + (max-min)*float64(n.Int64())/math.Pow10(precision)
	return math.Round(f*math.Pow10(precision)) / math.Pow10(precision), nil
}

// Choice 从切片中随机选择一个元素
func (g *Generator) Choice(items []string) (string, error) {
	if len(items) == 0 {
		return "", fmt.Errorf("empty items")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(items))))
	if err != nil {
		return "", err
	}

	return items[n.Int64()], nil
}

// Shuffle 随机打乱切片
func (g *Generator) Shuffle(items []string) error {
	for i := len(items) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := n.Int64()
		items[i], items[j] = items[j], items[i]
	}
	return nil
}
