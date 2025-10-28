# Nginx IP监控工具

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

自动监控Nginx访问日志，根据配置的阈值自动将违规IP加入黑名单，并支持企业微信通知。

## 功能特性

- ✅ **持续监控Nginx访问日志** - 实时监控并分析访问行为
- ✅ **智能IP封禁** - 根据访问次数和时间窗口自动封禁违规IP
- ✅ **时间窗口控制** - 在指定时间窗口内达到阈值才触发封禁
- ✅ **IP归属地查询** - 自动获取IP地理位置信息
- ✅ **企业微信推送** - 封禁事件实时通知
- ✅ **访问统计分析** - 详细的访问统计和周期报告
- ✅ **持久化存储** - 访问统计和封禁记录持久化保存
- ✅ **多日志格式支持** - 支持custom和combined两种Nginx日志格式
- ✅ **灵活日志级别** - 通过配置文件或命令行参数控制日志级别
- ✅ **IP白名单机制** - 保护信任的IP地址不被误封
- ✅ **周期统计报告** - 显示活跃IP、访问次数、封禁信息等

## 安装

### 环境要求

- Python 3.6+
- 依赖包见 `requirements.txt`

### 安装依赖

```bash
pip install -r requirements.txt
```

## 配置

### 编辑配置文件

编辑 `config.yaml` 文件：

```yaml
# Nginx日志文件路径
nginx_log_path: "/var/log/nginx/access.log"

# 日志格式: custom 或 combined
nginx_log_format: "custom"

# 需要监控的路径列表
monitor_paths:
  - "/resource_fhnz/api/user/send_valid_code"
  - "/api/login"
  - "/admin"

# 访问次数阈值（达到此次数将被封禁）
threshold: 10

# 时间窗口（秒），在此时间内达到阈值将触发封禁
threshold_duration: 288000

# 黑名单输出文件路径
blacklist_file: "ip_blacklist.conf"

# 白名单文件路径
whitelist_file: "whitelist.txt"

# 封禁信息持久化文件路径
blocked_ips_info_file: "blocked_ips_info.json"

# 访问统计持久化文件路径
ip_interface_stats_file: "ip_interface_stats.json"

# 检查间隔（秒）
check_interval: 60

# 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL (默认为DEBUG)
log_level: "INFO"

# 日志文件路径（默认为nginx_monitor.log）
log_file: "nginx_monitor.log"

# 企业微信webhook URL（可选）
wechat_webhook_url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY"
```

### 配置参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `nginx_log_path` | 字符串 | Nginx日志文件路径 |
| `nginx_log_format` | 字符串 | 日志格式: custom 或 combined |
| `monitor_paths` | 列表 | 需要监控的路径列表 |
| `threshold` | 整数 | 触发封禁的访问次数阈值 |
| `threshold_duration` | 整数 | 时间窗口（秒） |
| `blacklist_file` | 字符串 | 黑名单文件路径 |
| `whitelist_file` | 字符串 | 白名单文件路径 |
| `blocked_ips_info_file` | 字符串 | 封禁信息持久化文件路径 |
| `ip_interface_stats_file` | 字符串 | 访问统计持久化文件路径 |
| `check_interval` | 整数 | 检查间隔（秒） |
| `log_level` | 字符串 | 日志级别 |
| `log_file` | 字符串 | 日志输出文件路径 |
| `wechat_webhook_url` | 字符串 | 企业微信webhook URL（可选） |

### 配置白名单

编辑 `whitelist.txt`，每行一个IP地址：

```
127.0.0.1
192.168.1.1
```

## 使用方法

### 基本使用

运行监控程序：

```bash
python nginx_ip_monitor.py
```

或指定配置文件：

```bash
python nginx_ip_monitor.py config.yaml
```

### 日志级别配置

#### 方式1：通过配置文件

在 `config.yaml` 中设置：

```yaml
log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
```

#### 方式2：通过命令行参数

```bash
# 使用INFO级别
python nginx_ip_monitor.py config.yaml --log-level INFO

# 使用DEBUG级别
python nginx_ip_monitor.py config.yaml -l DEBUG

# 使用WARNING级别
python nginx_ip_monitor.py config.yaml --log-level WARNING
```

### 日志级别说明

- **DEBUG**: 详细调试信息（包括每个IP访问记录等）
- **INFO**: 重要操作信息（IP封禁、通知发送、周期统计等）
- **WARNING**: 警告信息
- **ERROR**: 错误信息
- **CRITICAL**: 严重错误

### 命令行参数

```bash
python nginx_ip_monitor.py [config_file] [options]

选项:
  --log-level, -l    日志级别（覆盖配置文件中的设置）
                     可选值: DEBUG, INFO, WARNING, ERROR, CRITICAL
  --help, -h         显示帮助信息
```

### 查看帮助

```bash
python nginx_ip_monitor.py --help
```

## Nginx配置

### 引入黑名单

将生成的黑名单配置引入到Nginx配置中：

```nginx
http {
    # 引入IP黑名单
    include ip_blacklist.conf;
    
    server {
        # ... 其他配置
    }
}
```

配置完成后，重新加载Nginx：

```bash
nginx -s reload
```

### 日志格式支持

#### Custom格式（推荐）

需要在 `nginx.conf` 中配置：

```nginx
log_format access_log '$remote_addr - $remote_user [$time_local] '
                     '"$request" $status $body_bytes_sent '
                     '"$http_referer" "$http_user_agent" '
                     'Host: "$host" '
                     'Request_URI: "$request_uri" '
                     'Domain: "$server_name" '
                     'Headers: "$http_authorization" "$http_cookie"';

access_log /var/log/nginx/access.log access_log;
```

#### Combined格式

标准的combined格式也支持：

```nginx
access_log /var/log/nginx/access.log combined;
```

## 统计分析

### 周期统计输出

每个监控周期结束时，程序会输出详细的统计信息：

```
================================================================================
[周期统计] 处理日志行数: 150
[周期统计] 本周期活跃IP数量: 25
[周期统计] 累计总访问次数: 1250
[封禁统计] 本周期新增封禁: 2 个
[封禁统计] 累计总封禁IP: 5 个
[周期封禁] 本周期封禁的IP: 192.168.1.100, 10.0.0.50
[访问统计] 累计访问次数>=10的IP+接口组合 (共123个，显示前50个):
  1. IP: 192.168.1.100, 接口: /api/login, 访问次数: 156
  2. IP: 10.0.0.50, 接口: /resource_fhnz/api/user/send_valid_code, 访问次数: 89
  ...
[封禁详情] 所有被封禁IP的访问统计:
  封禁IP: 192.168.1.100
    - 归属地: 中国-北京-北京
    - 封禁时间: 2024-01-15 10:30:00
    - 触发路径: /api/login
    - 时间窗口内访问次数: 15
    - 平均访问间隔: 8.00 秒/次
    - 总访问次数: 156
    - 访问的接口: /api/login(156次)
================================================================================
```

### 持久化存储

程序会自动将以下数据持久化到文件：

1. **`blocked_ips_info.json`** - 封禁IP的详细信息
   - IP地址
   - 封禁时间
   - 访问次数
   - 访问时长
   - 触发路径
   - 归属地信息

2. **`ip_interface_stats.json`** - IP访问统计
   - 每个IP访问每个接口的次数
   - 累计访问统计数据

程序重启后会自动加载这些持久化数据，继续累积统计。

### 访问统计特性

- **统计所有IP访问** - 包括白名单和已封禁IP的访问
- **按IP+接口分组** - 详细记录每个IP访问每个接口的次数
- **周期报告** - 每个监控周期输出访问统计摘要
- **前50排名** - 显示访问次数排名前50的IP+接口组合

## 企业微信通知

### 通知配置

在 `config.yaml` 中配置企业微信webhook URL：

```yaml
wechat_webhook_url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY"
```

### 通知内容

通知消息包含以下信息：
- **IP地址** - 被封禁的IP
- **归属地信息** - IP地理位置
- **命中路径** - 触发封禁的访问路径
- **阈值次数** - 时间窗口内的访问次数
- **封禁时间** - 封禁发生的时间
- **触发时长** - 时间窗口内的访问持续时间

### 通知示例

```
# Nginx IP封禁通知

**IP地址：** `192.168.1.100`
**归属地：** 中国-北京-北京
**命中路径：** `/api/login`
**阈值次数：** 15
**封禁时间：** 2024-01-15 10:30:00
**触发时长：** 120秒
```

## 时间窗口说明

配置了 `threshold_duration` 后，系统只会统计最近N秒内的访问次数。

**示例**：
- `threshold: 10`
- `threshold_duration: 300`

表示：在300秒（5分钟）内达到10次访问才会触发封禁，而不是累计所有历史的10次访问。

这可以避免长期累积的访问触发误封。

## 注意事项

⚠️ **重要提示**

1. **权限要求**：
   - 确保有足够的权限读取nginx日志文件
   - 确保有写入黑名单文件的权限

2. **Nginx重新加载**：
   - 被封禁的IP会被追加到黑名单文件
   - 需要手动执行 `nginx -s reload` 使封禁生效

3. **白名单保护**：
   - 白名单IP将不被监控和封禁
   - 封禁IP不会重复封禁

4. **日志文件**：
   - 日志文件会自动生成（`nginx_monitor.log`）
   - 建议将日志文件添加到 `.gitignore` 中

5. **时间窗口**：
   - 时间窗口从最后一次访问向前计算
   - 只有时间窗口内的访问会被计入统计

6. **持久化文件**：
   - `blocked_ips_info.json` - 封禁信息
   - `ip_interface_stats.json` - 访问统计
   - `ip_blacklist.conf` - Nginx黑名单配置
   - 这些文件在程序重启后会自动加载

7. **性能考虑**：
   - 定期检查日志文件大小
   - 建议定期归档历史日志

8. **企业微信通知**：
   - 如果未配置webhook URL，程序会跳过通知发送
   - 通知内容使用markdown_v2格式

## 许可证

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v1.0.0
- ✅ 初始版本发布
- ✅ 支持时间窗口控制
- ✅ 支持企业微信通知
- ✅ 支持持久化存储
- ✅ 支持统计分析
- ✅ 支持灵活的日志级别配置