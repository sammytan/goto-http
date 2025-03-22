# 配置文件说明

本目录包含 goto-http 的配置文件示例。你可以基于这些示例创建自己的配置文件。

## 配置文件格式

支持两种格式：
- YAML (.yaml, .yml)
- JSON (.json)

## 配置文件示例

- `config.example.yaml`: YAML格式的配置示例
- `config.example.json`: JSON格式的配置示例

## 使用方法

1. 复制示例配置文件：
```bash
# 使用YAML格式
cp config.example.yaml config.yaml

# 或使用JSON格式
cp config.example.json config.json
```

2. 编辑配置文件，修改相关参数

3. 运行程序时指定配置文件：
```bash
goto-http -config config.yaml
```

## 配置项说明

### GUI配置
- `gui.web.enable`: 是否启用Web界面
- `gui.web.port`: Web界面端口
- `gui.terminal.enable`: 是否启用终端界面

### 系统配置
- `system.max_procs`: 最大处理器数量
- `system.max_files`: 最大文件描述符数量
- `system.cpu_limit`: CPU使用限制(%)
- `system.mem_limit`: 内存使用限制(MB)

### 攻击配置
- `attack.target`: 目标URL
- `attack.method`: 请求方法(GET/POST/HEAD等)
- `attack.duration`: 攻击持续时间
- `attack.rate`: 每秒请求数
- `attack.workers`: 并发工作者数量
- `attack.timeout`: 请求超时时间
- `attack.mode`: 攻击模式(normal/flood/bypass/stealth/mixed)
- `attack.headers`: 自定义请求头
- `attack.body`: 请求体(POST请求)

### 代理配置
- `proxy.enable`: 是否启用代理
- `proxy.file`: 代理列表文件
- `proxy.api`: 代理API地址
- `proxy.timeout`: 代理超时时间
- `proxy.interval`: 代理检查间隔
- `proxy.max_fails`: 最大失败次数
- `proxy.countries`: 代理国家/地区列表
- `proxy.types`: 代理类型列表
- `proxy.rules`: 代理过滤规则

### 日志配置
- `log.file`: 日志文件路径
- `log.level`: 日志级别(debug/info/warn/error)
- `log.format`: 日志格式(text/json)

### 监控配置
- `monitor.enable`: 是否启用监控
- `monitor.interval`: 监控间隔
- `monitor.metrics`: 监控指标列表
- `monitor.alerts`: 告警规则列表

## 时间格式说明

支持以下时间单位：
- `ns`: 纳秒
- `us`: 微秒
- `ms`: 毫秒
- `s`: 秒
- `m`: 分钟
- `h`: 小时

例如：
- `5s`: 5秒
- `1m30s`: 1分30秒
- `2h`: 2小时

## 注意事项

1. 配置文件中的敏感信息（如API密钥）建议使用环境变量
2. 生产环境建议禁用debug模式
3. 代理配置请确保代理可用性
4. 监控告警阈值请根据实际情况调整 