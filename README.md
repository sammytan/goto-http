# Goto-HTTP 

   ______      __          __  __ _______ _______ ____  
  / ____/___  / /_____    / / / //_  __// /_/ _ \/ __ \ 
 / / __/ __ \/ __/ __ \  / /_/ /  / /  / __/  __/ /_/ /
/ /_/ / /_/ / /_/ /_/ / / __  /  / /  / /_/ ___/ ____/ 
\____/\____/\__/\____/ /_/ /_/  /_/   \__/_/  /_/      

Goto-HTTP is a high-performance HTTP stress testing tool with support for various attack modes, proxy configurations, and advanced features.

## Basic Usage

```
./goto-http --url <target_url> [options]
```

## Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| --url | -u | Target URL (required) | - |
| --method | -X | HTTP method | GET |
| --duration | -d | Attack duration in seconds | 60 |
| --rate | -r | Requests per second | 50 |
| --workers | -w | Number of concurrent connections | 10 |
| --mode | -m | Attack mode | - |
| --interval | -i | Request interval in milliseconds | 1000 |
| --timeout | -T | Request timeout in seconds | 30 |
| --debug | - | Enable debug mode | false |
| --gui | - | Enable terminal UI mode | false |
| --follow-redirect | - | Follow HTTP redirects automatically | false |
| --http2 | - | Enable HTTP/2 support | false |
| --keepalive | - | Enable HTTP keep-alive | false |
| --post-data | - | POST data for request body | - |
| --headers | - | Custom HTTP headers (format: "key1:value1;key2:value2") | - |
| --cookies | - | Custom cookies (format: "key1=value1;key2=value2") | - |
| --referer | - | Custom referer header | - |
| --bypass | - | Bypass methods (comma-separated) | - |

## Attack Modes

| Mode | Description |
|------|-------------|
| get-flood | Basic GET flood attack |
| post-flood | POST flood attack (use with --post-data) |
| head-flood | HEAD request flood attack |
| options-flood | OPTIONS request flood attack |
| trace-flood | TRACE request flood attack |
| range-flood | Range request flood attack |
| http2-get-flood | HTTP/2 GET flood attack (requires --http2 and HTTPS target) |
| smart-flood | Intelligent flood attack that adapts to target response |
| ws-flood | WebSocket flood attack (requires WebSocket URL: ws:// or wss://) |

## Proxy Options

| Option | Description |
|--------|-------------|
| --proxy-type, -P | Proxy type: none, file, api, server (default: none) |
| --nodes | Proxy node name(s), supports "all" or specific node names (default: all) |
| --proxy-timeout | Proxy timeout in seconds (default: 10) |
| --proxy-countrys | Filter proxies by country/region codes |

## User-Agent Options

| Option | Description |
|--------|-------------|
| --ua-type, -U | User-Agent type: random, mobile, desktop, etc. (default: random) |
| --ua-custom, -C | Path to custom User-Agent file |

## WebSocket Options

| Option | Description |
|--------|-------------|
| --ws-frame-size | WebSocket frame size in bytes (default: 1024) |
| --ws-compression | Enable WebSocket compression |

## Random Placeholders

Goto-HTTP supports dynamic random values in URLs and parameters using placeholders:

| Placeholder | Description |
|-------------|-------------|
| %RANDSTR% | Random string (8 characters) |
| %RANDSTRn% | Random string of n characters (e.g., %RANDSTR6%) |
| %RANDINT% | Random integer (1000-9999) |
| %RANDINTn% | Random integer of n digits (e.g., %RANDINT4%) |
| %TOKEN% | UUID-like random token |

Example: `--url http://example.com/%RANDSTR%.php?id=%RANDINT%`

## Redirects

Use `--follow-redirect` to automatically follow HTTP redirects (301, 302, 307, 308 status codes). Without this flag, the tool will stop at the redirect response and report it.

## Advanced Features

### HTTP/2 Support
Enable HTTP/2 with the `--http2` flag. This is automatically enabled for http2-* attack modes.

### Logging
Logs are stored in the `logs/` directory:
- `logs/target.log`: Target request logs
- `logs/error.log`: Error logs
- `logs/proxy.log`: Proxy-related logs
- `logs/app.log`: Application logs

### Terminal UI
Enable the interactive terminal dashboard with `--gui` to monitor attacks in real-time, showing:
- Request statistics
- Response codes distribution
- Network traffic
- Last requests with details
- Server IP distribution

## Examples

Basic GET flood attack:
```
./goto-http --url http://example.com -m get-flood -d 60 -r 100 -w 50
```

POST attack with data:
```
./goto-http --url http://example.com/api -m post-flood --post-data "user=test&action=login" -d 30
```

Using random values:
```
./goto-http --url http://example.com/%RANDSTR%.php?id=%RANDINT% -m get-flood
```

Using proxies:
```
./goto-http --url http://example.com -m get-flood --proxy-type file --nodes all
```

HTTP/2 attack with GUI:
```
./goto-http --url https://example.com -m http2-get-flood --http2 --gui
```

Following redirects:
```
./goto-http --url http://example.com -m get-flood --follow-redirect
```

WebSocket attack:
```
./goto-http --url ws://example.com/socket -m ws-flood -d 30
```
