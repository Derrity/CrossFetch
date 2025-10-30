# CrossFetch

> A lightweight HTTP fetch proxy designed to accelerate overseas downloads from a UNTOUCHABLE server.

注意：本项目由openai codex加工优化 注意辨别

服务部署后，用户只需将原始 URL 按以下格式重写即可：

```
https://你的域名/https://目标域名/路径
```

Rust 服务会从境外拉取资源并流式回传，方便 `wget`、`curl` 等工具使用。

## 功能特性

- 支持 `GET`、`HEAD`，并自动跟随最多 10 次 3xx 跳转（由 `reqwest` 完成）。
- 透传常见请求/响应头（含 `Range`），允许断点续传与大文件分块下载。
- 可通过环境变量自定义监听地址、上游 `User-Agent`，便于与现有网络策略兼容。
- 提供 Caddy 反向代理示例，快速接入 HTTPS 与自动证书。
 - 对 3xx 重定向自动重写 `Location` 头，确保客户端继续通过自定义域名访问后续链接。

## 仓库结构

```
crossfetch/   # Rust 代理服务源码
README.md     # 使用指南（当前文件）
Caddyfile     # Caddy 反向代理示例
```

## 快速开始

### 环境需求

- Rust 1.79+（建议 `rustup` 安装）
- Caddy 2.x（可选，用于暴露 TLS 服务）

### 本地运行

```bash
cd crossfetch
cargo run --release
```

默认监听 `0.0.0.0:3000`。

#### 环境变量

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND_ADDR` | `0.0.0.0:3000` | 代理服务监听地址 |
| `UPSTREAM_USER_AGENT` | `CrossFetch/0.1 (+https://xxx.com)` | 发往上游时使用的 UA |

### 使用示例

```bash
wget "https://xxx.com/https://github.com/user/project/releases/download/v1.0/app.tar.gz"
```

包含查询参数的 URL 建议整体加引号，或提前进行百分号编码：

```bash
curl -L "https://xxx.com/https://example.com/file%3Ftoken%3D123"
```

## 借助 Caddy 暴露 HTTPS

根目录提供 `Caddyfile` 示例，核心配置如下：

```
xxx.com {
    encode gzip zstd

    @proxy_methods {
        method GET HEAD
    }

    handle @proxy_methods {
        reverse_proxy 127.0.0.1:3000 {
            flush_interval -1
            transport http {
                versions 1.1
                keepalive 32
            }
        }
    }

    handle {
        respond 405 {
            body "405: method not allowed\n"
        }
    }

    log {
        output file /var/log/caddy/crossfetch.log {
            roll_size 10mb
            roll_keep 10
        }
        format single_field common_log
    }
}
```

部署步骤：

1. 保证 Rust 服务运行在 `127.0.0.1:3000`。
2. 将域名 `xxx.com` 解析到服务器公网 IP。
3. 启动 Caddy：
   ```bash
   sudo caddy run --config Caddyfile
   ```
4. 通过 `https://xxx.com/https://github.com/...` 发起下载。

Caddy 会自动申请/续期证书，并提供访问日志，方便后续分析与审计。

## 安全与生产建议

- **限制可访问的目标域名**：可在应用内增加白名单，或通过 Caddy/防火墙实现。
- **阻断私网 IP**：避免 SSRF，确保不会访问 127.0.0.0/8、10.0.0.0/8 等网段。
- **控制带宽与并发**：结合 Caddy `rate_limit`、`request_body` 插件或上游负载控制规则。
- **缓存/预热**：对于热门文件，可结合对象存储或 CDN 减少重复拉取的消耗。

## 后续路线

- 在响应阶段重写 `Location` 头，确保多级跳转保持自定义域名。
- 增强指标采集（Prometheus、OpenTelemetry），便于运维监控。
- 引入磁盘缓存或内存缓存模块，降低重复下载的压力。

欢迎提 Issue 或 PR，一起完善 CrossFetch。
