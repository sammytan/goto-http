package attack

import (
	"fmt"
	"goto-http/pkg/random"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// 随机变量正则表达式
	randVarRegex = regexp.MustCompile(`%([A-Z]+)(?:\:([^%]+))?%`)
)

// ReplaceRandomVars 替换字符串中的随机变量
func ReplaceRandomVars(input string) (string, error) {
	// 每次调用创建新的生成器实例，确保随机性
	gen := random.NewGenerator()

	result := randVarRegex.ReplaceAllStringFunc(input, func(match string) string {
		// 提取变量名和参数
		parts := randVarRegex.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		varName := parts[1]
		params := ""
		if len(parts) > 2 {
			params = parts[2]
		}

		// 根据变量类型生成随机值
		switch varName {
		case "RANDINT":
			if params != "" {
				// 解析范围参数
				rangeParts := strings.Split(params, "-")
				if len(rangeParts) == 2 {
					min, err1 := strconv.ParseInt(rangeParts[0], 10, 64)
					max, err2 := strconv.ParseInt(rangeParts[1], 10, 64)
					if err1 == nil && err2 == nil {
						if n, err := gen.IntRange(min, max); err == nil {
							return fmt.Sprintf("%d", n)
						}
					}
				}
			}
			// 默认范围
			if n, err := gen.Int(); err == nil {
				return fmt.Sprintf("%d", n)
			}

		case "RANDSTR":
			length := 8      // 默认长度
			charset := "all" // 默认字符集
			if params != "" {
				// 解析参数
				paramParts := strings.Split(params, ":")
				if len(paramParts) == 2 {
					charset = paramParts[0]
					if l, err := strconv.Atoi(paramParts[1]); err == nil {
						length = l
					}
				}
			}
			if s, err := gen.String(length, charset); err == nil {
				return s
			}

		case "RANDHEX":
			length := 16 // 默认长度
			if params != "" {
				if l, err := strconv.Atoi(params); err == nil {
					length = l
				}
			}
			if s, err := gen.Hex(length); err == nil {
				return s
			}

		case "UUID":
			if s, err := gen.UUID(); err == nil {
				return s
			}

		case "TIME":
			if params == "ms" {
				return fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
			}
			return fmt.Sprintf("%d", time.Now().Unix())

		case "XFF":
			if ip, err := gen.IPv4(); err == nil {
				return ip
			}

		case "RANDUSER":
			if s, err := gen.String(8, "lower"); err == nil {
				return s
			}

		case "RANDEMAIL":
			if s, err := gen.Email(); err == nil {
				return s
			}

		case "RANDPHONE":
			if s, err := gen.Phone(); err == nil {
				return s
			}

		case "RANDIPV4":
			if s, err := gen.IPv4(); err == nil {
				return s
			}

		case "RANDIPV6":
			if s, err := gen.IPv6(); err == nil {
				return s
			}
		}

		return match // 如果生成失败，保留原始字符串
	})

	return result, nil
}
