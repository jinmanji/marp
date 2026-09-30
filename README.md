# marp

[![build](https://github.com/jinmanji/marp/actions/workflows/.github/workflows/build.yml/badge.svg)](https://github.com/jinmanji/marp/actions/workflows/.github/workflows/build.yml)

首次运行自动注册 Cloudflare WARP 账号，使用 [usque](https://github.com/Diniboy1123/usque)
核心建立 MASQUE（Connect-IP / RFC 9484）隧道，并以**带用户名密码认证的 HTTP 代理与 SOCKS5 代理**对外提供服务。

- **账号注册与配置提取**参考 [wgcf](https://github.com/ViRb3/wgcf) 的流程：`POST /reg` 创建设备 →
  上传 P-256 公钥完成 MASQUE 入网 → 从返回体中提取对端公钥、端点地址与隧道内网 IP。
- **隧道核心**完全使用 usque：`api.PrepareTlsConfig` / `api.ConnectTunnel`，并复用其
  `config.Config` 账号文件格式，可直接与 usque 的 `config.json` 互通。
- **额外能力**：端点池（`ip:port`）、SNI 伪装（如 `recaptcha.net`）、QUIC 优先并自动回退 HTTP/2。

全程用户态运行，**不需要 root、不需要 TUN 设备**，Linux / macOS / Windows / Android 均可编译。

---

## 快速开始

```bash
go build -ldflags="-s -w" -o marp .

# 第一次运行：没有 config.json -> 生成配置 + 随机用户名密码 + 自动注册 WARP 账号
./marp

# 输出示例
# 未找到配置文件，已生成 config.json
# 已生成随机代理凭据: 用户名 "k3mzq7xapw" 密码 "Ty9bQ2vLmXp4Rz7Nc1Ha"
# 未找到 WARP 账号配置 warp.json，正在自动注册 ...
# WARP 账号注册成功，配置已保存到 warp.json
# ---------------- 代理信息 ----------------
# 用户名 : k3mzq7xapw
# 密码   : Ty9bQ2vLmXp4Rz7Nc1Ha
# HTTP   : http://k3mzq7xapw:Ty9bQ2vLmXp4Rz7Nc1Ha@127.0.0.1:8000
# SOCKS5 : socks5://k3mzq7xapw:Ty9bQ2vLmXp4Rz7Nc1Ha@127.0.0.1:1080
# WARP IP: 172.16.0.2 / 2606:4700:110:...
# 端点池 : 162.159.198.1:443
# SNI    : consumer-masque-proxy.cloudflareclient.com
# 模式   : auto
# ----------------------------------------
```

使用：

```bash
curl -x http://k3mzq7xapw:Ty9bQ2vLmXp4Rz7Nc1Ha@127.0.0.1:8000 https://www.cloudflare.com/cdn-cgi/trace
curl -x socks5h://k3mzq7xapw:Ty9bQ2vLmXp4Rz7Nc1Ha@127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

看到 `warp=on` / `warp=plus` 即表示隧道生效。

---

## 命令行

```
marp [run] [选项]        启动 HTTP / SOCKS5 代理（默认命令）
marp register [选项]    强制重新注册一个 WARP 账号
marp creds [选项]       打印当前代理认证信息
marp version            打印版本号
```

常用 `run` 选项：

| 选项 | 说明 |
| --- | --- |
| `-c, -config` | 应用配置文件路径（默认 `config.json`） |
| `-endpoints` | 覆盖端点池，逗号分隔的 `ip:port` |
| `-sni` | 覆盖 TLS SNI，可伪装为其他域名 |
| `-mode` | `auto`（默认）/ `quic` / `http2` |
| `-register` | 账号配置缺失时强制重新注册 |
| `-license` | 注册后绑定 WARP+ 许可证 |

### 示例：指定端点 + SNI 伪装

```bash
./marp \
  -endpoints 162.159.198.218:443,162.159.198.20:443,162.159.198.5:443 \
  -sni recaptcha.net
```

```
端点池 : 162.159.198.218:443, 162.159.198.20:443, 162.159.198.5:443
SNI    : recaptcha.net (伪装)
模式   : auto
```

SNI 伪装本身是有效的：实测使用账号下发的端点 + `recaptcha.net` 也能正常完成
Connect-IP 握手。需要区分两个独立的失败原因：

1. **端点必须是真正的 MASQUE 服务器。** TLS 层被拒（`CRYPTO_ERROR ... handshake failure`）
   通常意味着该 IP 不提供 MASQUE 服务，与 SNI 无关；程序会轮换端点池并给出提示。
2. **伪装 SNI 会改变证书校验对象。** 若端点公钥与账号记录的不一致，可设置
   `"insecure": true` 关闭公钥校验（会降低安全性）。

排查建议：先用账号下发的端点 + 真实 SNI 验证链路，再单独切换端点或 SNI。

实测结果（已入网账号）：

| 端点 | SNI | 结果 |
| --- | --- | --- |
| 账号下发 `162.159.198.2:443` | `consumer-masque-proxy.cloudflareclient.com` | `warp=on` |
| 账号下发 `162.159.198.2:443` | `recaptcha.net`（伪装） | `warp=on`，**伪装可用** |
| `162.159.198.218 / .20 / .5:443` | 真实 SNI | TLS 握手被拒，不是可用端点 |

即：伪装功能正常，需要更换的是端点。Cloudflare 下发的端点由 API 决定（本次为
`162.159.198.2`），不要硬编码到配置里——留空 `endpoints` 让程序使用账号下发的地址即可。

---

## 传输策略：QUIC 优先 + HTTP/2 回退

`mode = auto`（默认）时：

1. 优先使用 **QUIC / HTTP/3** 连接 MASQUE 端点；
2. 连续失败达到 `quic_failure_threshold`（默认 3）次后自动切换到 **TCP + TLS + HTTP/2**；
3. 在 H2 上工作 `h2_retry_interval`（默认 5m）后自动回切到 QUIC 重新探测；
4. 每次重连都会轮换端点池中的下一个地址。

UDP/443 被封锁时可用 `-mode http2` 强制走 TCP。

---

## 配置文件

首次运行自动生成 `config.json`（权限 `0600`），随后可以手工编辑。

```jsonc
{
  "listen": {
    "socks5": "127.0.0.1:1080",
    "http":   "127.0.0.1:8000"
  },
  "auth": {
    "enabled":  true,
    "username": "k3mzq7xapw",
    "password": "Ty9bQ2vLmXp4Rz7Nc1Ha"
  },
  "warp": {
    "config_file":   "warp.json",   // 账号配置（与 usque 的 config.json 同格式）
    "auto_register": true,          // 账号缺失时自动注册
    "accept_tos":    true,
    "device_name":   "marp",
    "model":         "PC",
    "locale":        "en_US",
    "team_token":    ""             // 填入 Zero Trust team token 即注册团队账号
  },
  "tunnel": {
    "endpoints": ["162.159.198.218:443", "162.159.198.20:443", "162.159.198.5:443"],
    "sni":       "consumer-masque-proxy.cloudflareclient.com",
    "mode":      "auto",
    "port":      443,
    "use_ipv6":  false,
    "keepalive": "30s",
    "dns":       ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
    "dns_timeout": "5s",
    "mtu":         1280,
    "reconnect_delay": "1s",
    "connect_timeout": "15s",
    "quic_failure_threshold": 3,
    "h2_retry_interval":      "5m",
    "initial_packet_size":    0,   // 0 = 启用 PMTU 探测
    "insecure":     false
  }
}
```

### 关键字段

| 字段 | 说明 |
| --- | --- |
| `auth.enabled` | 开启后必须同时提供用户名密码；缺失时会自动生成随机凭据并写回文件 |
| `tunnel.endpoints` | 端点池，可写 `ip` 或 `ip:port`（省略端口时使用 `tunnel.port`）；留空则使用账号下发的端点 |
| `tunnel.sni` | TLS SNI；填任意域名即可伪装 |
| `tunnel.mode` | `auto` / `quic` / `http2` |
| `tunnel.insecure` | 关闭端点公钥校验（配合 SNI 伪装使用，**降低安全性**） |
| `tunnel.dns` | 隧道内使用的 DNS，查询经由 WARP 发出 |
| `warp.team_token` | Zero Trust 团队令牌，留空为免费账号 |

### 随机凭据

- 配置文件不存在 → 生成完整配置，用户名 10 位小写字母、密码 20 位大小写字母+数字，`crypto/rand`。
- 配置文件存在但 `auth.enabled = true` 且缺少凭据 → 同样生成随机凭据并写回。
- 生成的凭据会打印在启动日志中，并持久化到 `config.json`（`0600`），重启后保持不变。

---

## WARP 账号文件 `warp.json`

与 usque 的 `config.json` 结构完全一致，可以互相拷贝：

```jsonc
{
  "private_key": "M...",        // base64(P-256 ASN.1 DER)，机密
  "endpoint_v4": "162.159.198.1",
  "endpoint_v6": "2606:4700:103::",
  "endpoint_h2_v4": "162.159.198.2",
  "endpoint_h2_v6": "",
  "endpoint_pub_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "license": "",
  "id": "00000000-0000-0000-0000-000000000000",
  "access_token": "...",
  "ipv4": "172.16.0.2",
  "ipv6": "2606:4700:110:..."
}
```

其它工具读取 usque 配置：

```bash
./marp creds            # 只看代理认证信息
./marp register -force   # 重新注册一个账号
./marp -license XXXX    # 注册并绑定 WARP+
```

---

## 开发

```bash
make build     # 编译
make test      # 单元测试 + 集成测试（全部离线，不访问 Cloudflare）
make vet       # go vet
make fmt       # gofmt
make clean
```

跨平台编译：

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o marp.exe .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o marp .
```

---

## 自动编译（GitHub Actions）

工作流位于 `.github/workflows/build.yml`。

**仅在以下两种情况触发，不监听 push / PR / 定时任务：**

| 触发方式 | 行为 |
| --- | --- |
| 手动触发（Actions 页面 Run workflow） | 编译全部产物并作为 workflow artifact 下载；勾选 `draft_release` 可顺便建一个 Draft Release |
| 发布 Release（`published`） | 编译全部产物，自动上传为该 Release 的附件并附带 `SHA256SUMS.txt` |

流水线：`test`（go vet + gofmt 校验 + go test）→ `build`（矩阵编译）→ `checksums` →

`attach-to-release` / `draft-release`。`checksums` 会先核对 9 个产物是否齐全（缺任何一个就退出 1），
所以**不会出现“发布成功但附件缺文件”**。任一环节失败都会阻断发布。

### VPS 一键安装

```bash
curl -fsSL "https://github.com/jinmanji/marp/releases/latest/download/marp-linux-$(uname -m|sed 's/x86_64/amd64/;s/aarch64\|arm64/arm64/;s/armv8l/armv7/;s/armv7l/armv7/;s/armv6l/armv6/')" -o /tmp/marp && sudo install -m755 /tmp/marp /usr/local/bin/marp && marp version
```

启动（后台常驻，首次运行会自动注册 WARP 账号并生成随机用户名密码）：

```bash
marp &            # 默认 HTTP :8000 / SOCKS5 :1080，配置写入 ./config.json
```

### Alpine Linux

所有 Linux 产物均以 `CGO_ENABLED=0` 编译，是**完全静态、不含动态链接器**的 ELF，
所以**同一份 `marp-linux-*` 产物在 Alpine（musl）和 glibc 发行版上都能跑**，
不需要单独的 musl 构建。

原生安装（Alpine 默认没有 `sudo`，用 `doas` 或直接 root）：

```bash
apk add --no-cache curl
curl -fsSL "https://github.com/jinmanji/marp/releases/latest/download/marp-linux-$(uname -m|sed 's/x86_64/amd64/;s/aarch64\|arm64/arm64/;s/armv8l/armv7/;s/armv7l/armv7/;s/armv6l/armv6/')" -o /tmp/marp && doas install -m755 /tmp/marp /usr/local/bin/marp && marp version
```

Docker：

```bash
make alpine-image                      # 或 docker build -f Dockerfile.alpine -t marp:alpine .
docker run -d --name marp -p 8000:8000 -p 1080:1080 -v marp-data:/etc/marp marp:alpine
```

镜像基于 `alpine:3.20`，以非 root 用户 `marp` 运行，`config.json` 与 `warp.json` 放在
`/etc/marp` 卷里持久化。注意 Alpine 基础镜像默认**不带 CA 根证书**，镜像里已装
`ca-certificates`，否则无法与 Cloudflare 建立 TLS。

CI 会把真实产物丢进 `node:20-alpine` 容器里跑一遍（`verify-alpine` job），
并检查所有 linux 产物没有 `PT_INTERP`——因此“能在 Alpine 上跑”不是口头承诺，
而是每次发布都会被验证的事实。

编译矩阵（均为 `CGO_ENABLED=0` + `-trimpath`，产物可复现）：

| 系统 | 架构 | 产物名 |
| --- | --- | --- |
| linux | amd64 / arm64 | `marp-linux-amd64` / `marp-linux-arm64` |
| linux | armv6 / armv7 | `marp-linux-armv6` / `marp-linux-armv7` |
| windows | amd64 / arm64 | `marp-windows-amd64.exe` / `marp-windows-arm64.exe` |
| darwin | amd64 / arm64 | `marp-darwin-amd64` / `marp-darwin-arm64` |
| android | arm64 | `marp-android-arm64` |

> `android/arm`（32 位）无法用 `CGO_ENABLED=0` 构建，需要外部链接，因此不在矩阵内。

版本号在 CI 中通过 `-ldflags "-X main.version=..."` 注入：发布时取 Release tag，
手动触发时取输入框（留空则用提交短 SHA），`./marp version` 可以验证。

手动触发一次构建：Actions 页面 → Build workflow → Run workflow。

### 项目结构

```
main.go                      CLI、隧道装配、代理服务装配
Dockerfile.alpine            Alpine/musl 镜像定义
internal/appconfig/          配置加载 / 默认值 / 随机凭据 / 持久化
internal/warpapi/            wgcf 风格注册、配置提取、账号文件读写
internal/tunnel/             端点解析 + QUIC/HTTP2 回退的隧道守护
internal/socks5/             带用户名密码认证的 SOCKS5 服务端
internal/httpproxy/          带 Basic 认证的 HTTP 代理服务端（CONNECT + 转发）
tools/mkaccount/             仅用于本地冒烟测试：生成一份假账号文件（无法真正连通）
```

本地冒烟测试（在一台不能访问 Cloudflare 的机器上也能把程序跑起来）：

```bash
go run ./tools/mkaccount /tmp/warp.json
./marp -c /tmp/config.json
```

`tools/mkaccount` 生成的密钥未经 Cloudflare 入网，隧道一定会报 `login failed`；
它只用于验证监听端口、认证、端点轮换与 QUIC/H2 回退逻辑。

---

## 已知限制

- 代理为 **TCP** 转发（SOCKS5 仅实现 `CONNECT`，未实现 `UDP ASSOCIATE`）。
- HTTP 代理本身不加密，TLS 由端到端的客户端提供（CONNECT 隧道）。
- SOCKS5 与 HTTP 代理共用同一组用户名密码。
- 未经 Cloudflare 官方审查，稳定性与性能不及官方客户端；数据泵全在用户态。

## 致谢

- [usque](https://github.com/Diniboy1123/usque) —— MASQUE 核心（MIT）
- [wgcf](https://github.com/ViRb3/wgcf) —— WARP 账号注册与配置提取流程参考（MIT）
- [connect-ip-go](https://github.com/Diniboy1123/connect-ip-go) —— RFC 9484 实现
- [quic-go](https://github.com/quic-go/quic-go)、[wireguard-go](https://git.zx2c4.com/wireguard-go/)

本项目与 Cloudflare 无任何关联。Cloudflare WARP 是 Cloudflare, Inc. 的商标。
