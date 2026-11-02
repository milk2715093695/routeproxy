# routeproxy

`routeproxy` 是一个 TCP 转发代理，旨在根据规则自动决定直连还是使用上游代理。

## 目录

- [routeproxy](#routeproxy)
  - [目录](#目录)
  - [构建](#构建)
  - [配置说明](#配置说明)
  - [规则文件](#规则文件)
  - [运行](#运行)
  - [来源与许可](#来源与许可)
  - [安装](#安装)

## 构建

```bash
cargo fmt --check
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Android 交叉编译、macOS/Termux/Windows 打包脚本在 `packaging/` 下。

## 配置说明

`routeproxy` 只读取一份 TOML。示例：

```toml
[proxy]
mode = "http"
listen = ["127.0.0.1:6045", "[::1]:6045"]
upstream = "127.0.0.1:9910"

[rules]
file = "/path/to/routeproxy/rules.toml"
reload = true

[logging]
file = "/path/to/routeproxy/routeproxy.log"
level = "info"
max_size_mb = 5
keep = 3
```

字段说明：

| 段 | 字段 | 必填 | 默认 | 说明 |
| --- | --- | --- | --- | --- |
| `proxy` | `mode` | 是 | — | `http` 或 `transparent`。桌面平台（macOS/Linux/Windows）推荐 `http`，可直接配合系统/全局代理；`transparent` 仅用于 Android Magisk 模块，且必须只有一个 `127.0.0.1` 监听地址。 |
| `proxy` | `listen` | 是 | — | 监听地址数组，必须是 loopback；端口不能为 0，不能重复。HTTP 模式可同时监听 IPv4/IPv6；`transparent` 只能一个 IPv4 loopback。 |
| `proxy` | `upstream` | 是 | — | 上游 HTTP 代理地址（CONNECT），不是 SOCKS5。端口不能为 0；不能是 unspecified/multicast/broadcast，也不能等于任一 `listen` 地址。 |
| `rules` | `file` | 是 | — | 最终 `rules.toml` 快照路径；运行时只读。发布包附带一份非个人通用 seed，部署方可用自己的最终快照替换。 |
| `rules` | `reload` | 否 | `true` | 监听 `rules.file` 变化并热加载；失败保留旧快照，按退避重试。设为 `false` 时需重启进程。 |
| `logging` | `file` | 是 | — | 日志文件路径；按大小轮转。 |
| `logging` | `level` | 是 | — | `trace`、`debug`、`info`、`warn`、`error`、`off`，大小写不敏感；非法值启动即失败。 |
| `logging` | `max_size_mb` | 否 | `5` | 单个日志文件上限，必须大于 0。 |
| `logging` | `keep` | 否 | `3` | 保留的轮转文件数，必须大于 0。 |

补充：

- 路径建议使用绝对路径；相对路径按进程当前目录解析。
- `transparent` 借 Linux/Android 透明重定向工作；实际只给 Android Magisk 模块使用。Linux 虽然技术上可用，但推荐 `http` + 全局代理，macOS/Windows 只能使用 `http`。
- `transparent` 只对 80 端口的明文 HTTP 读取 `Host`；HTTPS 不解析 SNI，按目标 IP 决策。80 端口可用显式 Direct `Host` 把 foreign IP 提升为直连；HTTPS 仍无法做到这一点。若某个代理域名解析到直连 IP，HTTPS 请求仍会走直连，这是当前版本的已知边界，不是规则失效。
- HTTP 模式最多 1024 个连接槽、512 个活跃请求/隧道；响应头返回后释放活跃请求许可，慢速下载只占连接槽。`100.64.0.0/10`（CGNAT/Tailscale）按私有地址直连。
- 域名规则是后缀匹配；只写 `com` 会匹配所有 `.com` 域名，这是预期语义，`rules check` 不会把它当错误。

## 规则文件

`rules.file` 指向一份最终 `rules.toml`，运行时只读取该快照。`routeproxy` 不生产专属规则，也不下载上游规则；它提供无策略的通用 `rules build`/`rules check`，数量下限、哨兵、路径和部署由部署方负责。

仓库根目录的 `rules.toml` 是一份非个人通用 seed，发布包会把它作为 `rules.seed.toml` 或 `rules.toml` 附带。部署方可以复制并替换成自己的最终快照：

```bash
cp rules.toml /path/to/routeproxy/rules.toml
```

部署前校验快照：

```bash
routeproxy rules check --file /path/to/rules.toml
```

0.1.1 起校验更严格：域名不接受 `_`、空标签或连续点，CIDR 不接受尾点；旧快照如有这些写法，需要先修正。

`rules check` 只校验 schema、`upstream_sha`、域名/CIDR 格式和时间戳，不检查数量下限、哨兵或文件大小；成功时输出：

```text
规则校验通过: /path/to/rules.toml (schema=1, sha=..., direct=138, proxy=35, local_tlds=2, cidrs=10012)
```

通用构建器只读显式传入的文件，不读配置、环境变量、git 或网络：

```bash
routeproxy rules build \
  --direct /path/to/direct-domains.txt \
  --proxy /path/to/proxy-domains.txt \
  --local-tlds /path/to/local-tlds.txt \
  --cidrs /path/to/cidrs.txt \
  --upstream-sha <40 位十六进制> \
  --updated-at <RFC3339> \
  --output /path/to/rules.toml
```

四类文件都可重复、可缺省；空文件或只有注释的文件合法。构建会排序、去重、规范化 CIDR，并在 direct/proxy 精确同名时让 direct 胜出；不删除后缀遮蔽项。输出先写同目录临时文件，再原子替换目标。

`rules.toml` 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema` | integer | 目前为 `1`。 |
| `upstream_sha` | string，可省略 | 规则来源/版本标记，运行时和 `rules check` 可留空；`rules build` 要求 40 位十六进制。 |
| `updated_at` | RFC 3339 string | 快照生成时间。 |
| `direct` | string[] | 直连域名后缀。 |
| `proxy` | string[] | 代理域名后缀。 |
| `local_tlds` | string[] | 本地 TLD 后缀，必须带前导点（如 `".test"`）；可为空。 |
| `cidrs` | string[] | 直连 CIDR；可为空。 |

Android 模块使用 `/data/adb/routeproxy/rules.toml`；其他平台在配置里指向对应路径。

## 运行

```bash
routeproxy run --config /path/to/config.toml
routeproxy doctor --config /path/to/config.toml
routeproxy rules build --direct ... --proxy ... --local-tlds ... --cidrs ... --upstream-sha ... --updated-at ... --output ...
routeproxy rules check --file /path/to/rules.toml
routeproxy version
```

| 命令 | 作用 | 主要选项 |
| --- | --- | --- |
| `run` | 前台启动代理，阻塞运行，由 launchd / runit / 计划任务 / Magisk service 托管。 | `--config <PATH>`（必填）；`--log-level <LEVEL>` 覆盖配置中的日志级别。 |
| `doctor` | 启动前自检；不启动服务，也不创建空日志文件。 | `--config <PATH>`（必填）；`--probe <HOST\|IP>` 额外打印该目标的直连/代理决策。 |
| `rules build` | 通用离线构建器：解析、合并、去重、排序、结构校验和原子写。 | `--direct/--proxy/--local-tlds/--cidrs <FILE>` 均可重复、可缺省；`--upstream-sha <SHA>`、`--updated-at <RFC3339>`、`--output <PATH>` 必填。 |
| `rules check` | 校验最终规则快照；部署前闸门。 | `--file <PATH>`（必填）。 |
| `version` | 打印版本和 build id。 | — |

`run`：

- 先校验配置、日志级别和规则文件，再初始化日志并启动监听；任一步失败立即退出，退出码为 1。
- `rules.reload = true` 时启动规则文件监听；热加载失败会保留旧快照并退避重试。
- `--log-level` 只影响本次进程，不修改配置文件；支持 `trace`、`debug`、`info`、`warn`、`error`、`off`。
- `http` 模式等待客户端把 HTTP/HTTPS 代理指向 `proxy.listen`；`transparent` 模式依赖 Android/Linux 的透明重定向规则。
- 进程不自行 daemon 化；停止、重启和开机自启由平台服务管理器负责。

`doctor`：

- 检查配置解析、监听地址能否绑定、上游 TCP 是否可达（3 秒超时）、规则快照能否加载、日志路径是否可写。
- 监听地址已被占用时只提示 “已被占用（服务可能已在运行）”，不算错误；其他绑定失败、规则加载失败、日志不可写会返回失败。
- 上游不可达只是 warning；规则更新时间超过 14 天会提示已过期。
- `--probe` 接受域名或 IP，使用当前规则输出决策；规则文件不可用时跳过。
- 有 error 时退出码为 1；只有 warning 时退出码为 0。

`rules check` 输出类似：

```text
规则校验通过: /path/to/rules.toml (schema=1, sha=..., direct=138, proxy=35, local_tlds=2, cidrs=10012)
```

`version` 输出类似：

```text
routeproxy 0.1.1 (routeproxy-build-id:0.1.1@<commit>|)
```

## 来源与许可

routeproxy 源代码采用 Apache License 2.0，完整文本见
[LICENSE](LICENSE)。规则 seed 与域名/CIDR/private 决策顺序来自
[gfw-pac](https://github.com/zhiyi7/gfw-pac)（Apache License 2.0），
并与 `pacproxy` 的实现保持同源；路由决策在 Rust 中重写。

规则 seed 中的 CIDR 数据来自
[Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)（经 gfw-pac
同步），采用 **CC-BY-SA-4.0**；其中中国大陆 CIDR 上游为
[china-operator-ip](https://github.com/gaoyifan/china-operator-ip)（MIT）。
`rules.toml` 作为生成的数据文件适用 CC-BY-SA-4.0；Rust 源代码适用
Apache-2.0。本项目对数据做了格式转换、去重和 TOML 合并，修改说明见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，完整数据许可文本见
[LICENSE-DATA](LICENSE-DATA)，版权声明见 [NOTICE](NOTICE)。

## 安装

安装包提供 `routeproxy` 可执行文件、`rules.toml` seed、`config.toml.example`、`LICENSE`、`LICENSE-DATA`、`NOTICE` 和 `THIRD_PARTY_NOTICES.md`；Android 模块带透明模式示例。配置文件按「配置说明」复制后修改，规则文件复制 seed 后由部署方替换为最终快照。安装后先运行：

```bash
routeproxy doctor --config /path/to/config.toml
```

平台差异：

- macOS：可执行文件放到 `~/.local/bin` 或 `/usr/local/bin`；配置放到 `~/.config/routeproxy/config.toml`；由 launchd 托管。
- Linux：可执行文件放到 `/usr/local/bin`；配置可放 `/etc/routeproxy/config.toml` 或用户目录；由 systemd 或用户服务托管。推荐 `mode = "http"` 并配合系统/全局代理。
- Termux：解压 aarch64 包，配置放到 `~/.config/routeproxy/config.toml`；由 runit 服务托管。
- Windows：安装 `routeproxy.exe`，配置放到 `%USERPROFILE%\.config\routeproxy\config.toml`；由计划任务托管。
- Android：使用 Magisk 模块；配置在 `/data/adb/routeproxy/config.toml`，规则在 `/data/adb/routeproxy/rules.toml`；模块服务负责启动和透明重定向。

启动前确认：

```bash
routeproxy doctor --config /path/to/config.toml
```

`doctor` 有 error 时退出码为 1；只有 warning 时退出码为 0。
