# DomainMonitor

监控处于**待删除阶段**（pendingDelete / redemptionPeriod）的域名，一旦状态变化（变得可注册 / 被人抢注）立即通过 Server酱³ 推送到微信。

## 功能特性

- **双协议查询**：优先 RDAP（结构化 JSON，误判率低），RDAP 查询失败自动降级 WHOIS；未配置 RDAP 的后缀直接走 WHOIS
- **按后缀配置查询地址**：每个 TLD 可单独配置 whois 服务器与 RDAP 地址（支持 `{domain}` 占位符）
- **后缀并发、组内串行**：不同后缀并行监控互不拖累，同一后缀内严格单线程顺序查询
- **随机休眠**：每次查询完成后在 `[sleep_min, sleep_max]` 内随机休眠，节奏不可预测、天然避开注册局限流
- **查询频率按状态分级**：赎回期默认 24h 确认一次、待删除期快速轮询、可注册后 30min 一次，不做无意义的浪费查询
- **配置热更新**：运行中修改 config.yaml 自动生效（增/删域名与后缀、换 whois/RDAP 地址、改查询参数与推送凭据）；新配置非法时自动回退旧配置，监控不中断
- **状态机与推送**：状态变化时推送一次（含赎回期 ↔ 待删除的阶段变化）；域名被注册后自动移出监控列表
- **状态持久化**：`state.json` 记录每个域名的当前状态与历史，重启不会重复推送

## 构建

```bash
go build -o domainmonitor .
```

唯一第三方依赖：`gopkg.in/yaml.v3`。

## 使用

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml：填入 sendkey、待监控域名、后缀地址

# 先手动验证某个域名的查询是否正常（不推送、不写状态文件）
./domainmonitor -c config.yaml check example.com

# 启动常驻监控
./domainmonitor -c config.yaml
```

`check` 输出示例：

```
域名: foo.com
后缀: com
状态: pending_delete
通道: rdap
依据: RDAP status: pending delete
```

## 配置说明

| 配置项 | 说明 |
|---|---|
| `query.sleep_min` / `sleep_max` | 每次查询完成后的随机休眠区间，如 `0.5s` ~ `5s` |
| `query.timeout` | 单次 RDAP/WHOIS 查询超时 |
| `query.retries` | RDAP 与 WHOIS 都失败时的整体重试次数（退避 2s、4s…） |
| `query.intervals.redemption_period` | 赎回期的检查间隔，默认 `24h`（状态稳定且长达约 30 天，一天确认一次足够） |
| `query.intervals.pending_delete` | 待删除期的检查间隔，默认 `0s`（每轮都查，即用 `sleep_min~sleep_max` 的快节奏——随时可能释放的关键窗口） |
| `query.intervals.available` | 可注册后的检查间隔，默认 `30m`（只需偶尔确认是否被他人注册） |
| `query.proxy` | RDAP 的 HTTP 代理（WHOIS 为原生 TCP，不走代理） |
| `serverchan.uid` / `sendkey` | Server酱³ 凭据；`uid` 留空时自动从 `sctp{uid}t...` 提取 |
| `serverchan.tags` | 推送标签 |
| `tlds[].suffix` | 后缀，按**最长匹配**（支持 `co.uk` 等多级后缀） |
| `tlds[].whois` | WHOIS 服务器（`host` 或 `host:port`，默认 43 端口） |
| `tlds[].rdap` | RDAP 地址，支持 `{domain}` 占位符；留空则只用 WHOIS |
| `tlds[].notfound_marker` | 可选，覆盖该后缀 WHOIS"未注册"判定关键词 |
| `domains` | 监控列表，应为 pendingDelete 状态域名；IDN 域名请写 punycode |
| `remove_when` | 移出监控时机：`registered`（默认）/ `available` |
| `state_file` | 状态文件路径 |
| `log_level` | `debug` / `info` / `warn` / `error`（支持热更新） |
| `reload.enabled` / `reload.interval` | 配置热更新开关与检测间隔（默认启用 / 1s） |
| `notify_stage_change` | 赎回期 ↔ 待删除的阶段变化是否推送（默认 true） |
| `notify_on_error` | 连续失败 20 次时是否推送提醒（默认否） |

## 工作原理

### 状态归一化

赎回期与待删除期是删除流程的两个先后阶段，分别独立跟踪（都能看到"进入 5 天倒计时"这个关键信号）：

| 内部状态 | 含义 | RDAP 判定 | WHOIS 判定 |
|---|---|---|---|
| `redemption_period` | 赎回期（通常约 30 天） | status 含 `redemption period` | 含 `redemptionPeriod` |
| `pending_delete` | 待删除（通常约 5 天后释放） | status 含 `pending delete` | 含 `pendingDelete` |
| `available` | 可注册 | HTTP 404 | 命中"未注册"词表（`no match`、`not found`、`no data found`、`no entries found`、`no matching record`、`status: free` 等） |
| `registered` | 已注册 | 200 且状态正常 | 含 `domain name:` / `registrar:` / 状态行等注册信息 |
| `error` | 查询失败（不代表域名真实状态） | 超时/5xx/429 | 超时/疑似限流页 |

判定优先级：错误/限流 > 未注册 > pendingDelete > redemptionPeriod > 已注册。

### 状态变化与移除

- 新加入的域名初始状态记为 `pending_delete`；若首次查询就发现它已不在待删除状态（赎回期/可注册/已注册），会**立即推送**，避免错过
- `赎回期 → 待删除`：推送 ⏳（“约 5 天后释放”，可用 `notify_stage_change: false` 关闭这类阶段推送）
- `待删除 → 可注册`：推送 🎉，继续监控
- `可注册 → 已注册`（被人抢注，或你自己注册了）：再推送 ⚠️，然后移出监控列表
- `赎回期/待删除 → 已注册`：推送 ⚠️ 并移出（说明被重新注册了）
- `remove_when: available` 时，检测到可注册即推送并移除，不再跟踪后续注册
- 移除通过 `state.json` 中 `removed: true` 实现，不修改 config.yaml

### 查询节奏按状态分级

检查间隔取自域名**当前存储的状态**，因此状态一变就立刻切换节奏（赎回期 → 待删除后自动回到快速轮询）：

| 域名当前状态 | 默认检查间隔 | 理由 |
|---|---|---|
| `redemption_period` | 24h | 赎回期约 30 天且状态稳定，高频查询纯属浪费，还容易踩注册局限流 |
| `pending_delete` | 0（每轮都查） | 释放随时可能发生，是关键窗口，用 `sleep_min~sleep_max` 随机节奏快查 |
| `available` | 30m | 只需确认是否被他人注册，没必要持续高频 |
| `registered` | 终态，移出列表 | — |

`sleep_min`/`sleep_max` 负责“相邻两次查询之间的节奏”，`intervals` 负责“同一个域名隔多久再查”。当一轮里所有域名都没到期时，worker 会睡到最早的到期时间（分片休眠，单次最多 10s），所以热更新新增的域名也能很快被开始监控。

### 配置热更新

运行中修改 config.yaml 会自动生效（默认启用，每 1s 检测一次文件内容）：

- **新增域名**：自动写入状态（初始 `pending_delete`）并开始监控；若属于新后缀，自动为该后缀启动 worker
- **移除域名**：停止监控并清理其状态；重新加入则从头开始（可能因首次比对立即推送一次）
- **增删后缀 / 改 whois、RDAP 地址**：重建查询器，下一轮查询生效
- **改查询参数**（休眠区间、状态检查间隔、超时、重试、代理）：下一轮生效
- **改推送凭据/标签、`remove_when`、`log_level`**：立即生效
- **新配置非法**：记录错误并继续使用旧配置，监控不中断；`domains` 允许临时为空（暂停监控，等待下次更新）

实现：按文件内容 sha256 轮询检测变更 → 校验通过后整体替换运行时快照（`atomic.Pointer`）→ 唤醒调度器补齐新后缀 worker。

### 推送格式

调用 Server酱³：`POST https://<uid>.push.ft07.com/send/<sendkey>.send`，正文为 Markdown，包含域名、状态变化、检测时间、查询通道与判定依据。

## 实现说明：为什么不用 viper

viper 提供 `WatchConfig` / `OnConfigChange`，但它只解决“监听文件 + 重新解析”；热更新的真正工作量在**应用变更**：新增域名要建状态条目并启动新后缀 worker、移除域名要清理状态、换地址要重建查询器、非法配置要保留旧配置不中断监控——无论用不用 viper 这部分都得手写。而引入 viper 的代价是 15 个直接依赖（require 块 84 行，连带 `cloud.google.com/go`、firestore、grpc 等）。

因此本项目用**内容哈希轮询**（约 60 行、零新依赖、对编辑器改名保存/挂载卷替换同样有效）+ **原子快照替换**实现热更新，全项目仍只依赖 `gopkg.in/yaml.v3`。若确实需要 fsnotify 级别的事件驱动，`watchConfig` 是隔离的几十行，可以单独替换。

## 注意事项

- **限流**：注册局对查询频率有限制，`sleep_min` 建议不要低于 0.5s；某后缀查询持续失败不影响其他后缀
- **误判兜底**：WHOIS 为文本协议，若某注册局的"未注册"响应不在默认词表里，可用 `notfound_marker` 覆盖，或直接为该后缀配置 RDAP
- **state.json**：删除某域名对应的条目（或整个文件）可重置该域名的监控状态；把域名从 config 的 `domains` 里删掉即可停止监控
- **Server酱配额**：状态变化是低频事件，正常使用不会触及每日推送上限

## systemd 示例

```ini
[Unit]
Description=Domain pendingDelete monitor
After=network-online.target

[Service]
WorkingDirectory=/opt/domainmonitor
ExecStart=/opt/domainmonitor/domainmonitor -c config.yaml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```
