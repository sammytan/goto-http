# 代理配置文件说明

## 基本配置
- `version`: 配置文件版本号

## 代理配置 (proxy)
- `enable`: 是否启用代理
- `type`: 代理类型，可选值：none, local, api

### 代理提供者 (providers)
每个提供者包含以下字段：
- `name`: 提供者名称，用于标识
- `api_url`: API接口地址
- `api_key`: (可选) API密钥，如果API需要密钥认证则提供
- `api_token`: (可选) API请求头认证token，如果API需要token认证则提供，格式通常为 "Bearer your_token_here"
- `weight`: 权重，用于负载均衡
- `countries`: 支持的国家/地区列表
- `protocols`: 支持的协议类型
- `params`: API请求参数
  - `timeout`: 超时时间(毫秒)
  - `anonymity`: 匿名度
  - `ssl`: 是否支持SSL

### 代理设置 (settings)
- `timeout`: 代理请求超时时间
- `interval`: 代理检查间隔
- `max_fails`: 最大失败次数
- `retry_times`: 重试次数
- `failover`: 是否启用故障转移
- `validate_enable`: 是否启用代理验证
- `validate_url`: 验证URL
- `validate_timeout`: 验证超时时间

### 代理筛选条件 (filters)
- `latency`: 延迟筛选
  - `max`: 最大延迟(毫秒)
  - `min`: 最小延迟(毫秒)
- `uptime`: 在线时间筛选
  - `min`: 最小在线率(%)
- `success_rate`: 成功率筛选
  - `min`: 最小成功率(%)
- `bandwidth`: 带宽筛选
  - `min`: 最小带宽
  - `unit`: 带宽单位(mbps)

### 代理轮换设置 (rotation)
- `enable`: 是否启用轮换
- `interval`: 轮换间隔
- `strategy`: 轮换策略，可选值：round-robin, random, weighted
- `max_uses`: 单个代理最大使用次数

### 代理缓存设置 (cache)
- `enable`: 是否启用缓存
- `size`: 缓存大小
- `ttl`: 缓存有效期

## 日志配置 (log)
- `file`: 日志文件路径
- `level`: 日志级别，可选值：debug, info, warn, error
- `format`: 日志格式，可选值：text, json

## 监控配置 (monitor)
- `enable`: 是否启用监控
- `interval`: 监控间隔
- `metrics`: 监控指标列表
  - `proxy_health`: 代理健康度
  - `proxy_latency`: 代理延迟
  - `proxy_success_rate`: 代理成功率
  - `proxy_availability`: 代理可用性

### 告警规则 (alerts)
- `name`: 告警名称
- `metric`: 告警指标
- `threshold`: 告警阈值
- `duration`: 持续时间
- `action`: 告警动作，可选值：reload_proxies, notify

## 使用示例

1. 基本使用：
```bash
./test -target "http://example.com" -proxy-config configs/api_proxy.json
```

2. 与攻击配置结合使用：
```bash
./test -target "http://example.com" -config configs/attack.json -proxy-config configs/api_proxy.json
```

## 注意事项

1. API认证：
   - 可以通过 `api_key` 或 `api_token` 进行认证
   - `api_key` 通常在URL参数或请求头中
   - `api_token` 通常在请求头的 Authorization 字段中

2. 代理验证：
   - 建议启用代理验证功能
   - 验证URL最好选择稳定且响应快的网站
   - 可以设置合适的验证超时时间

3. 性能优化：
   - 合理设置缓存大小和TTL
   - 根据实际需求调整轮换策略
   - 设置适当的筛选条件避免代理池过小 