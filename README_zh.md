# trans_proxy

[English](README.md)

一个适用于 macOS 的透明代理，拦截由 pf 重定向的 TCP 流量，并通过上游 HTTP CONNECT 代理进行转发。

设计用于在作为局域网中其他设备的旁路由（网关）的 Mac 上运行。

```
[客户端设备] --网关--> [macOS pf rdr] --> [trans_proxy :8443]
                                                      |
                                                      v
                                                 [上游 HTTP CONNECT 代理]
                                                      |
                                                      v
                                                 [原始目标地址]
```

## 功能特性

- **pf 集成** — 使用 `/dev/pf` 上的 `DIOCNATLOOK` ioctl 从 pf 的 NAT 状态表中恢复原始目标地址
- **SNI 提取** — 窥探 TLS ClientHello 以提取主机名，发送正确的 `CONNECT host:port` 而非原始 IP
- **DNS 转发器** — 直接监听网关接口（端口 53）的局域网客户端 DNS 查询，构建 IP→域名查找表。支持 DNS-over-HTTPS (DoH) 和传统 UDP 上游。
- **基于 Anchor 的 pf 规则** — 不会覆盖你现有的防火墙配置
- **守护进程模式** — 作为后台进程运行，支持 PID 文件和日志文件
- **launchd 服务** — 安装为 macOS LaunchDaemon，开机自动启动
- **异步 I/O** — 基于 tokio 构建，每个连接独立任务调度

## 系统要求

- macOS 12+（使用 pf 和 `DIOCNATLOOK` ioctl）
- Rust 1.70+ 和 Cargo
- Root 权限（用于访问 `/dev/pf` 和绑定端口 53）
- 一个上游 HTTP CONNECT 代理（例如 Squid、mitmproxy 或任何支持 CONNECT 的代理）

## 构建

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/madeye/trans_proxy.git
cd trans_proxy

# 构建发布版本
cargo build --release

# 二进制文件位于 ./target/release/trans_proxy
```

### 验证构建

```bash
cargo test
./target/release/trans_proxy --help
```

## 快速开始

本示例假设你的上游 HTTP 代理运行在 `127.0.0.1:1082`，局域网接口为 `en0`。

```bash
# 第 1 步：启动透明代理，并在网关接口上启用 DNS
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns

# 或以守护进程方式运行
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d

# 第 2 步：设置 pf 重定向（在另一个终端中，或使用 -d 时在同一终端中）
sudo scripts/pf_setup.sh en0 8443

# 第 3 步：配置客户端设备（参见下方"客户端设置"）

# 第 4 步：使用完毕后，拆除配置
sudo scripts/pf_teardown.sh
# 如果以守护进程方式运行，停止它
sudo kill $(cat /var/run/trans_proxy.pid)
```

## 使用方法

### 启动代理

代理需要 root 权限才能打开 `/dev/pf` 进行 NAT 查找：

```bash
# 最简配置 — 仅代理，不启用 DNS
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port>

# 在网关接口上启用 DNS（自动检测 en0 IP，监听端口 53）
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns

# 指定不同的接口
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns --interface en1

# 手动覆盖 DNS 监听地址
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns-listen 192.168.1.42:53

# 使用指定的 DoH 提供商
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns --dns-upstream https://dns.google/dns-query

# 使用传统 UDP DNS 而非 DoH
sudo ./target/release/trans_proxy \
  --upstream-proxy <proxy_host>:<proxy_port> \
  --dns --dns-upstream 8.8.8.8:53

# 以后台守护进程方式运行
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d

# 守护进程模式，自定义 PID 和日志文件
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d --pid-file /tmp/trans_proxy.pid \
  --log-file /tmp/trans_proxy.log
```

### 命令行选项

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--listen-addr` | `0.0.0.0:8443` | 代理监听的地址和端口 |
| `--upstream-proxy` | *（必填）* | 上游 HTTP CONNECT 代理地址（`host:port`） |
| `--log-level` | `info` | 日志级别：`trace`、`debug`、`info`、`warn`、`error` |
| `--dns` | 关闭 | 在网关接口上启用 DNS 转发器（端口 53） |
| `--interface` | `en0` | DNS 自动检测使用的网络接口（与 `--dns` 配合使用） |
| `--dns-listen` | *（自动）* | 覆盖 DNS 监听地址（例如 `192.168.1.42:53`） |
| `--dns-upstream` | `https://cloudflare-dns.com/dns-query` | 上游 DNS：UDP 使用 `host:port`，DoH 使用 `https://` URL |
| `-d` / `--daemon` | 关闭 | 以后台守护进程方式运行 |
| `--pid-file` | `/var/run/trans_proxy.pid` | PID 文件路径（与 `--daemon` 配合使用） |
| `--log-file` | `/var/log/trans_proxy.log`（守护进程）/ stderr | 日志文件路径 |
| `--install` | 关闭 | 安装为 macOS launchd 服务（LaunchDaemon） |
| `--uninstall` | 关闭 | 卸载 macOS launchd 服务 |

### 设置 pf 重定向

附带的脚本通过 anchor 管理 pf 规则（不会干扰现有的防火墙规则）。
DNS 不再需要 pf 重定向 — trans_proxy 直接监听端口 53。

```bash
# 设置 HTTP/HTTPS 重定向
sudo scripts/pf_setup.sh <interface> [proxy_port]
sudo scripts/pf_setup.sh en0 8443
```

设置脚本会打印网关 IP 和配置摘要：

```
==> Enabling IP forwarding
==> Loading pf anchor 'trans_proxy'
==> Enabling pf
==> Verifying anchor rules

Done.
  Gateway IP:  192.168.1.42 (en0)
  HTTP/HTTPS:  ports 80,443 -> 127.0.0.1:8443
  DNS:         use --dns flag to listen on 192.168.1.42:53 directly

Configure client devices to use 192.168.1.42 as their gateway.
Set DNS server to 192.168.1.42 on client devices.
Run scripts/pf_teardown.sh to undo.
```

拆除配置：

```bash
sudo scripts/pf_teardown.sh
```

这会清除 anchor 规则并禁用 IP 转发。pf 本身保持启用状态 — 运行 `sudo pfctl -d` 可完全禁用。

### 守护进程模式

以后台进程方式运行 trans_proxy：

```bash
# 以守护进程方式启动
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns -d

# 检查状态
cat /var/run/trans_proxy.pid
tail -f /var/log/trans_proxy.log

# 停止
sudo kill $(cat /var/run/trans_proxy.pid)
```

守护进程模式下：
- 进程会 fork 到后台并脱离终端
- 写入 PID 文件（默认 `/var/run/trans_proxy.pid`）
- 日志写入文件（默认 `/var/log/trans_proxy.log`）而非 stderr
- 退出时自动清理 PID 文件

### 服务安装（launchd）

将 trans_proxy 安装为 macOS LaunchDaemon，使其在开机时自动启动，崩溃后自动重启：

```bash
# 使用你需要的选项进行安装
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --install
```

这将会：
- 将二进制文件复制到 `/usr/local/bin/trans_proxy`
- 在 `/Library/LaunchDaemons/com.github.madeye.trans_proxy.plist` 生成 launchd plist 文件
- 配置 `RunAtLoad` 和 `KeepAlive` 以实现自动启动和重启
- 日志输出到 `/var/log/trans_proxy.log`
- 立即加载并启动服务

使用 `launchctl` 管理服务：

```bash
sudo launchctl stop  com.github.madeye.trans_proxy
sudo launchctl start com.github.madeye.trans_proxy
```

卸载：

```bash
sudo trans_proxy --uninstall
```

这会卸载服务、删除 plist 文件并移除已安装的二进制文件。

**注意：** 使用 `--install` 时不需要 `--daemon`、`--pid-file` 和 `--log-file` 参数 — launchd 会直接管理进程生命周期。

### 客户端设置

在每台你希望通过代理路由的设备上：

1. **设置默认网关** 为 Mac 的 IP 地址（由设置脚本显示）
2. **设置 DNS 服务器** 为 Mac 的 IP 地址（如果使用了 `--dns`）

#### macOS / iOS
设置 → Wi-Fi → (i) → 配置 IP → 手动 → 路由器：`<gateway_ip>`，DNS：`<gateway_ip>`

#### Windows
设置 → 网络 → Wi-Fi → 属性 → 编辑 IP → 手动 → 网关：`<gateway_ip>`，DNS：`<gateway_ip>`

#### Linux
```bash
sudo ip route replace default via <gateway_ip>
echo "nameserver <gateway_ip>" | sudo tee /etc/resolv.conf
```

#### Android
设置 → Wi-Fi → 长按网络 → 修改 → 高级 → IP 设置：静态 → 网关：`<gateway_ip>`，DNS：`<gateway_ip>`

## 工作原理

### 流量流程

1. 客户端设备发送数据包到 `example.com:443`（解析为例如 `93.184.216.34`）
2. 数据包到达 Mac 的局域网接口（Mac 是网关）
3. macOS pf `rdr` 规则将目标地址重写为 `127.0.0.1:8443`
4. trans_proxy 接受连接
5. `DIOCNATLOOK` ioctl 从 pf 的 NAT 状态表中恢复原始目标地址（`93.184.216.34:443`）
6. trans_proxy 窥探 TLS ClientHello 以提取 SNI（`example.com`）
7. 向上游代理发送 `CONNECT example.com:443 HTTP/1.1`
8. 在客户端和上游代理之间进行双向数据中继

### 主机名解析

代理使用以下回退链为 CONNECT 请求解析主机名：

1. **SNI 提取** — 解析 TLS ClientHello 以读取 Server Name Indication 扩展（仅端口 443）。无需 TLS 终止或证书生成。
2. **DNS 表查找** — 如果启用了 `--dns`，内置 DNS 转发器会从 A 记录响应中记录 IP→域名映射。适用于 HTTP（端口 80）和 HTTPS（端口 443）。
3. **原始 IP** — 如果无法确定主机名，则回退到 IP 地址。

### 为什么使用 DIOCNATLOOK？

macOS pf 的 `rdr` 规则会在套接字层看到之前重写目标地址。这意味着在已接受的连接上调用 `getsockname()` 返回的是代理自身的地址，而非原始目标地址。`DIOCNATLOOK` ioctl 查询 pf 的 NAT 状态表以恢复原始目标地址 — 这与 mitmproxy 使用的方法相同。

## 故障排除

### "Failed to open /dev/pf"
使用 `sudo` 运行。代理需要 root 权限才能访问 `/dev/pf`。

### "No ALTQ support in kernel"
这是 `pfctl` 的无害警告。macOS 不包含 ALTQ — pf 重定向功能在没有它的情况下也能正常工作。

### "DIOCNATLOOK failed"
- 确保 pf 规则已加载：`sudo pfctl -a trans_proxy -s rules`
- 确保 pf 已启用：`sudo pfctl -s info | head -1`
- 检查流量是否确实到达了预期的接口

### 连接挂起或超时
- 验证上游代理是否正在运行并接受 CONNECT 请求
- 使用 `--log-level debug` 查看详细的每连接日志
- 确保 IP 转发已启用：`sysctl net.inet.ip.forwarding`（应为 `1`）

### 客户端设备 DNS 无法解析
- 确保已设置 `--dns` 且 DNS 转发器正在运行
- 检查 trans_proxy 日志是否显示 `DNS forwarder listening on <ip>:53`
- 测试：`dig @<gateway_ip> example.com`

## 许可证

[MIT](LICENSE)
