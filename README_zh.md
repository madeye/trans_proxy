# trans_proxy

[English](README.md)

一个适用于 macOS 和 Linux 的透明代理，拦截由操作系统防火墙重定向的 TCP 流量，并通过上游 HTTP CONNECT 或 SOCKS5 代理进行转发。

设计用于在作为局域网中其他设备旁路由（网关）的机器上运行。

```
[客户端设备] --网关--> [NAT 重定向] --> [trans_proxy :8443]
                                                      |
                                                      v
                                                 [上游代理 (HTTP CONNECT / SOCKS5)]
                                                      |
                                                      v
                                                 [原始目标地址]
```

## 功能特性

- **macOS pf 集成** — 使用 `/dev/pf` 上的 `DIOCNATLOOK` ioctl 从 pf 的 NAT 状态表中恢复原始目标地址
- **Linux nftables 集成** — 使用 `SO_ORIGINAL_DST` getsockopt 从 nftables 重定向中恢复原始目标地址
- **SOCKS5 上游支持** — 使用 SOCKS5 代理作为上游，支持可选的用户名/密码认证（RFC 1928/1929）。通过 `socks5://host:port` 或 `socks5://user:pass@host:port` 选择
- **SNI 提取** — 窥探 TLS ClientHello 以提取主机名，发送正确的 `CONNECT host:port` 而非原始 IP
- **DNS 转发器** — 直接监听网关接口（端口 53）的局域网客户端 DNS 查询，构建 IP→域名查找表。支持 DNS-over-HTTPS (DoH)（HTTP/2 连接池、TTL 缓存、查询合并）和传统 UDP 上游。
- **基于 Anchor 的 pf 规则**（macOS）/ **nftables 表**（Linux）— 不会覆盖现有防火墙配置
- **守护进程模式** — 作为后台进程运行，支持 PID 文件和日志文件
- **系统服务** — macOS 使用 launchd，Linux 使用 systemd。Linux 上通过 ExecStartPre/ExecStopPost 自动管理 nftables NAT 规则
- **异步 I/O** — 基于 tokio 构建，每个连接独立任务调度
- **端到端测试** — 完整的端到端测试套件在 Linux 和 macOS 上运行真实的 nftables/pf + 代理流水线

## 系统要求

- **macOS**：macOS 12+（使用 pf 和 `DIOCNATLOOK` ioctl）
- **Linux**：内核 3.7+ 且支持 nftables
- Rust 1.70+ 和 Cargo（从源码构建时需要）
- Root 权限（用于 NAT 查找和绑定端口 53）
- 一个上游 HTTP CONNECT 或 SOCKS5 代理（例如 Squid、Dante、ssh -D 或任何支持 CONNECT/SOCKS5 的代理）

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

### macOS

本示例假设你的上游代理运行在 `127.0.0.1:1082`，局域网接口为 `en0`。

```bash
# 第 1 步：启动透明代理，并在网关接口上启用 DNS
# HTTP CONNECT 上游：
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns

# 或使用 SOCKS5 上游：
# sudo ./target/release/trans_proxy \
#   --upstream-proxy socks5://127.0.0.1:1080 \
#   --dns

# 第 2 步：设置 pf 重定向
sudo scripts/pf_setup.sh en0 8443

# 第 3 步：配置客户端设备（参见下方"客户端设置"）

# 第 4 步：使用完毕后，拆除配置
sudo scripts/pf_teardown.sh
sudo kill $(cat /var/run/trans_proxy.pid)
```

### Linux

本示例假设你的上游代理运行在 `127.0.0.1:7890`，局域网接口为 `eth0`。

```bash
# 第 1 步：启动透明代理，并启用 DNS
sudo ./trans_proxy \
  --upstream-proxy 127.0.0.1:7890 \
  --dns --interface eth0

# 第 2 步：设置 nftables 重定向
sudo scripts/nftables_setup.sh eth0 8443

# 第 3 步：配置客户端设备（参见下方"客户端设置"）

# 第 4 步：使用完毕后，拆除配置
sudo scripts/nftables_teardown.sh
sudo kill $(cat /var/run/trans_proxy.pid)
```

## 使用方法

### 启动代理

代理需要 root 权限进行 NAT 查找（macOS 上为 `/dev/pf`，Linux 上为 `SO_ORIGINAL_DST`）：

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

# 使用 SOCKS5 上游代理
sudo ./target/release/trans_proxy \
  --upstream-proxy socks5://127.0.0.1:1080 \
  --dns

# SOCKS5 用户名/密码认证
sudo ./target/release/trans_proxy \
  --upstream-proxy socks5://user:pass@127.0.0.1:1080 \
  --dns

# 仅重定向指定端口（默认：所有 TCP）
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --ports 22,80,443
```

### 命令行选项

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--listen-addr` | `0.0.0.0:8443` | 代理监听的地址和端口 |
| `--upstream-proxy` | *（必填）* | 上游代理：`host:port` 或 `http://host:port` 为 HTTP CONNECT，`socks5://host:port` 或 `socks5://user:pass@host:port` 为 SOCKS5 |
| `--log-level` | `info` | 日志级别：`trace`、`debug`、`info`、`warn`、`error` |
| `--dns` | 关闭 | 在网关接口上启用 DNS 转发器（端口 53） |
| `--interface` | `en0`（macOS）/ `eth0`（Linux） | DNS 自动检测使用的网络接口（与 `--dns` 配合使用） |
| `--dns-listen` | *（自动）* | 覆盖 DNS 监听地址（例如 `192.168.1.42:53`） |
| `--dns-upstream` | `https://cloudflare-dns.com/dns-query` | 上游 DNS：UDP 使用 `host:port`，DoH 使用 `https://` URL |
| `-d` / `--daemon` | 关闭 | 以后台守护进程方式运行 |
| `--pid-file` | `/var/run/trans_proxy.pid` | PID 文件路径（与 `--daemon` 配合使用） |
| `--log-file` | `/var/log/trans_proxy.log`（守护进程）/ stderr | 日志文件路径 |
| `--local-traffic` | 关闭 | 同时拦截网关本机发出的流量（不仅仅是转发的局域网流量） |
| `--fwmark` | `1` | Linux 上用于防止回环的防火墙标记（与 `--local-traffic` 配合使用） |
| `--ports` | *（所有 TCP）* | 要重定向的 TCP 端口列表，逗号分隔（例如 `22,80,443`）。未指定时重定向所有 TCP 流量 |
| `--install` | 关闭 | 安装为系统服务（macOS 使用 launchd，Linux 使用 systemd） |
| `--uninstall` | 关闭 | 卸载系统服务 |

### 设置 NAT 重定向

#### macOS (pf)

```bash
sudo scripts/pf_setup.sh <interface> [proxy_port] [upstream_proxy] [ports]
sudo scripts/pf_setup.sh en0 8443                              # 所有 TCP
sudo scripts/pf_setup.sh en0 8443 "" 80,443                    # 仅端口 80,443
sudo scripts/pf_setup.sh en0 8443 127.0.0.1:1082              # 所有 TCP + 本地流量

# 拆除配置
sudo scripts/pf_teardown.sh
```

#### Linux (nftables)

```bash
sudo scripts/nftables_setup.sh <interface> [proxy_port] [fwmark] [upstream_proxy] [ports]
sudo scripts/nftables_setup.sh eth0 8443                                  # 所有 TCP
sudo scripts/nftables_setup.sh eth0 8443 "" "" 80,443                     # 仅端口 80,443
sudo scripts/nftables_setup.sh eth0 8443 1 127.0.0.1:7890                # 所有 TCP + 本地流量

# 拆除配置
sudo scripts/nftables_teardown.sh
```

### Linux 内核优化

针对高吞吐量代理工作负载，优化内核参数和文件描述符限制：

```bash
sudo scripts/optimize_linux.sh
```

该脚本调整 sysctl 设置（TCP 缓冲区、积压队列、连接回收、TCP Fast Open）并提高文件描述符限制。基于 [shadowsocks 优化指南](https://shadowsocks.org/doc/advanced.html#optimize-the-shadowsocks-server-on-linux)。

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

### 服务安装

安装为系统服务，开机自动启动：

```bash
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --install
```

**macOS** 上安装为 LaunchDaemon，**Linux** 上安装为 systemd 服务（自动管理 nftables 设置/拆除 — 服务启动时创建 NAT 重定向规则，停止时自动移除）。

卸载：

```bash
sudo trans_proxy --uninstall
```

### 本机流量拦截

默认情况下，trans_proxy 仅拦截来自局域网客户端经过网关**转发的流量**。如需同时拦截网关本机发出的流量，请使用 `--local-traffic`：

```bash
sudo ./target/release/trans_proxy \
  --upstream-proxy 127.0.0.1:1082 \
  --dns --local-traffic --install
```

#### 工作原理

回环防护是自动的，无需创建专用系统用户：

- **Linux**：在出站 socket 上设置 `SO_MARK`（fwmark），nftables OUTPUT 链跳过带标记的数据包
- **macOS**：当上游代理在本地时，设置 `IP_BOUND_IF` 将出站 socket 绑定到 `lo0`，并通过 `pass out quick` pf 规则排除上游代理目标地址

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
2. 数据包到达网关的局域网接口
3. NAT 重定向规则将目标地址重写为 `127.0.0.1:8443`（macOS 使用 pf，Linux 使用 nftables）
4. trans_proxy 接受连接
5. 恢复原始目标地址（macOS 使用 `DIOCNATLOOK`，Linux 使用 `SO_ORIGINAL_DST`）
6. trans_proxy 窥探 TLS ClientHello 以提取 SNI（`example.com`）
7. 向上游代理发送 `CONNECT example.com:443`（HTTP CONNECT 或 SOCKS5）
8. 在客户端和上游代理之间进行双向数据中继

### 主机名解析

代理使用以下回退链为 CONNECT 请求解析主机名：

1. **SNI 提取** — 解析 TLS ClientHello 以读取 Server Name Indication 扩展（仅端口 443）。无需 TLS 终止或证书生成。
2. **DNS 表查找** — 如果启用了 `--dns`，内置 DNS 转发器会从 A 记录响应中记录 IP→域名映射。适用于 HTTP（端口 80）和 HTTPS（端口 443）。
3. **原始 IP** — 如果无法确定主机名，则回退到 IP 地址。

### 原始目标地址恢复

NAT 重定向规则会在套接字层看到之前重写目标地址。trans_proxy 使用平台特定的机制恢复原始目标地址：

- **macOS**：`DIOCNATLOOK` ioctl 查询 pf 的 NAT 状态表（与 mitmproxy 使用的方法相同）
- **Linux**：`SO_ORIGINAL_DST` getsockopt 从已接受的套接字 fd 恢复重定向前的目标地址

## 故障排除

### macOS："Failed to open /dev/pf"
使用 `sudo` 运行。代理需要 root 权限才能访问 `/dev/pf`。

### macOS："No ALTQ support in kernel"
这是 `pfctl` 的无害警告。macOS 不包含 ALTQ — pf 重定向功能在没有它的情况下也能正常工作。

### macOS："DIOCNATLOOK failed"
- 确保 pf 规则已加载：`sudo pfctl -a trans_proxy -s rules`
- 确保 pf 已启用：`sudo pfctl -s info | head -1`
- 检查流量是否确实到达了预期的接口

### Linux："SO_ORIGINAL_DST failed"
- 确保 nftables 重定向规则生效：`sudo nft list table ip trans_proxy`
- 确保 IP 转发已启用：`sysctl net.ipv4.ip_forward`（应为 `1`）

### 连接挂起或超时
- 验证上游代理是否正在运行并接受 CONNECT 请求
- 使用 `--log-level debug` 查看详细的每连接日志
- 确保 IP 转发已启用

### 客户端设备 DNS 无法解析
- 确保已设置 `--dns` 且 DNS 转发器正在运行
- 检查 trans_proxy 日志是否显示 `DNS forwarder listening on <ip>:53`
- 测试：`dig @<gateway_ip> example.com`

## 许可证

[MIT](LICENSE)
