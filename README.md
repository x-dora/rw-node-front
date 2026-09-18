# rw-node-front

[`rw-node`](https://github.com/x-dora/rw-node) 部署方案的前置分流进程，取代原先的
Caddy + inbound watcher 组合。

在**一个对外端口**上按连接首字节分流，供 PaaS 等只允许暴露单个端口的场景使用：

```
"SSH-" 前缀              -> sshd-lite
TLS (0x16)               -> 按 SNI 转到 REALITY inbound，其余转 node API
明文 HTTP                -> 按路径裸转发到 inbound 端口
                            健康检查、node API、静态伪装页由本进程处理
```

## 为什么不是 Caddy

原方案用 Caddy 的 layer4 listener wrapper 做同样的分流，外加一个后台 watcher 轮询
`/internal/get-config` 并热重载 Caddyfile。实测下来有两个问题：

**数据路径不零拷贝。** `rchar`/`wchar` 计数显示 Caddy 在 layer4 直通、file_server、
reverse_proxy 三条路径上，每个字节都要走一遍用户态 `read()`/`write()`——搬运
256 MiB 时 `rchar` 增加 256 MiB。原因是 caddy-l4 会把连接包装一层，`io.Copy` 的
`TCPConn.ReadFrom` 快路径失效。而两端都是未被包装的 `*net.TCPConn` 时，Linux 上
会命中内核 `splice(2)`，同样的 256 MiB 传输 `rchar` 只增加 189 字节。在 CPU 配额
被压到 0.15 核的 PaaS 上，这个差别直接换算成可承载带宽。

**组件太重。** Caddy 二进制 48 MB、常驻 46 MiB；watcher 还要跑一个 Python 进程
（26 MiB）来解析配置。而本进程是零第三方依赖的静态二进制，空载 RSS 约 3 MiB。

配置同步改用轮询而非长轮询：那需要在 `rw-node-go` 里加配置变更通知，而它的定位是
对齐官方 `remnawave/node` 的 Panel-facing contract，塞进前端专用的推送机制不合适。
轮询的代价在这里很低——解析只有一份 Go 实现、没有跨进程热重载、失败时保留上一份
可用路由。

## 运行配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HTTP_FRONT_PORT` | `$PORT` 或 `3000` | 对外监听端口 |
| `HTTP_FRONT_HOST` | `0.0.0.0` | 监听地址 |
| `NODE_PORT` | `2222` | node API 端口（TLS 兜底目标） |
| `INTERNAL_REST_PORT` | `61001` | 轮询 `/internal/get-config` 的端口 |
| `XHTTP_UPSTREAM_PORT` | `8080` | `/xh-*` 兜底上游 |
| `WS_UPSTREAM_PORT` | `8880` | `/ws-*` 兜底上游 |
| `SSH_ENABLED` | `false` | 是否在对外端口上提供 SSH 入口 |
| `SSH_PORT` | `22222` | sshd-lite 的本地端口 |
| `FRONT_SITE_DIR` | 空 | 静态伪装页目录（兼容旧名 `CADDY_SITE_DIR`） |
| `SECRET_KEY` | 空 | 用于派生 Panel SNI，缺失时不做 SNI 门控 |
| `INBOUND_WATCHER_INTERVAL` | `15` | 轮询间隔，秒或 Go duration 字符串 |

## 分流细节

判定顺序与原先 Caddyfile 的 `handle` 顺序一致，改动时不要调换：

1. `/health` 由本进程应答
2. `/node/*`、`/vision/*` 反代到 node API（HTTPS，带派生的 Panel SNI）
3. `rw-node-go` 下发的 inbound 路径 → 对应端口（**裸转发**）
4. `/xh-*` → xhttp 兜底端口，`/ws-*` → ws 兜底端口（**裸转发**）
5. 其余 → 静态伪装页

第 3、4 步刻意走裸转发而不是 `httputil.ReverseProxy`：后者在协议升级后同样是
用户态 `io.CopyBuffer`，ws/xhttp 这个主流量就和 Caddy 一样吃不到 splice。

TLS 连接按 ClientHello 里的 SNI 选路，命中配置下发的 REALITY `serverNames` 才转到
对应 inbound，其余（含 Panel SNI）一律是 node API。

## 开发

```bash
mise run test    # 单元测试
mise run lint    # golangci-lint
mise run build   # 产出 bin/rw-node-front
```

零第三方依赖，只用标准库——包括 ClientHello 的 SNI 解析（`clienthello.go`）。
之所以不复用 `xray-core` 的 `SniffTLS`，是因为那会把整棵依赖树拖进这个几 MiB 的
转发进程。

## 发布

推 `v*` tag 触发 `.github/workflows/release.yml`，产出：

```
rw-node-front-linux-64.tar.gz          # amd64
rw-node-front-linux-arm64-v8a.tar.gz   # arm64
*.dgst                                  # md5/sha1/sha256/sha512
```

`rw-node` 仓库通过 `.front-version` 记录引用的版本，由 Renovate 更新。
