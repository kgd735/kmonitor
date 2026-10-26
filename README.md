# KUI x Server Monitor Pro

KUI 是一个部署在**单个 Cloudflare Worker** 上的代理节点管理与服务器探针面板：

- Worker Assets 托管前端（`static/`）与 VPS 安装组件（`static/vps/`）；
- D1 保存配置、用户、节点、流量与探针数据；
- Durable Objects（`VpsPresence` / `DashboardHub`）提供实时 WebSocket 状态；
- VPS 上运行 Python Agent（`agent.py`）负责探针上报与 sing-box 节点管理；
- 住宅 IP 代理引擎（源自 Free-Residential-IP-Proxy-Controller-Sec）已融合进本 Worker，
  不需要额外部署任何控制器。

## 功能

**面板与订阅**

- 服务器与节点管理：面板生成一键部署命令，VPS 以 root 执行后自动回连；
- 节点协议：XTLS-Reality（含 H2 / gRPC 传输变体）、Hysteria2、TUIC、Trojan、
  AnyTLS、Naive、VLESS-Argo、Socks5、Dokodemo-door；支持"8 合 1"批量下发；
- 多用户与用户组：按组分配服务器/节点可见范围；订阅令牌、流量配额、到期时间、
  流量按期重置；
- 订阅导出：通用订阅与 Clash / Mihomo 格式（含 AnyTLS）；订阅保护开关；
  订阅 token 支持 `Authorization: Bearer` 头传递（兼容 `?token=` 查询参数）；
- 第三方订阅导入：拉取外部订阅并纳入节点池统一管理。

**探针与实时**

- Agent 上报 CPU、内存、磁盘、网络速率、TCP/UDP 连接数、运行时长与线路延迟
  （HTTP ping 测速，目标主机名白名单校验）；
- 探针全景大盘：多套预设主题、自定义 CSS 与背景；公开探针页（WebSocket 实时更新，
  观众连接频率自适应）；
- 实时通道内置于主 Worker：Agent 在线状态、面板即时配置刷新均走 Durable Objects，
  无需单独部署 Realtime Worker；
- Worker Cron 每 5 分钟检查离线节点；可选 Telegram 告警（离线/恢复通知）。

**节点出口**

- 每个节点可独立设置出口模式：原生、WARP（IPv4 / IPv6 / 双栈）、住宅代理、
  手动 SOCKS5；支持全局/分流（按分类）代理策略；
- 住宅出口经本机住宅引擎的 SOCKS5 出站（`127.0.0.1:<住宅全局端口>`）。

**住宅代理（融合版 FRP）**

- 控制器逻辑运行在本 Worker 的 `/api/proxy/*`，数据存 D1 的
  `frp_global_config` / `frp_server_config` / `frp_servers` 三张表；
- 能力与独立版 FRP 对齐：全局/单机国家策略、手动指定节点 IP、强制换 IP、
  单节点配置/切换/删除/远程卸载、VPNGate 国家列表、SOCKS5 订阅提取；
- 面板沿用原有住宅页面，Worker 负责把 FRP 的节点字段适配为面板格式。

## 架构

```text
浏览器 / VPS Agent
        |
Cloudflare Worker（src/worker.js 单入口）
  |- Worker Assets：前端与 VPS 安装文件
  |- /api/*：面板、订阅、探针、住宅模块接口
  |- /agent/ws、/dashboard/*、/public/*：内置实时服务
  |- Cron（*/5 * * * *）：离线节点检查（可选外部触发，CRON_SECRET 保护）
  |- D1（DB）：配置、用户、节点、流量、探针与住宅数据
  `- Durable Objects：VpsPresence（Agent 在线状态）、DashboardHub（大盘快照）
```

## 部署

### 一键部署

> 前置要求：先 fork 本仓库，在你 fork 的 `wrangler.jsonc` 里把 `database_id` 的占位符
> 换成你自己的 D1 ID（`npx wrangler d1 create kui-worker` 获取），再点部署按钮。
> 直接用本仓库点按钮会因为占位符 ID 部署失败。

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/kuangdash/kui-worker)

1. 点击上方按钮，登录 Cloudflare 并确认 Worker 名称；
2. 部署时确认 D1 绑定 `DB` 与两个 Durable Objects 绑定（`VPS_PRESENCE`、
   `DASHBOARD_HUB`）存在，不要删除；
3. 按下一节设置 Secret 并重新部署后，再打开 Worker 地址登录
   （未设置 `ADMIN_PASSWORD` 时登录会被直接拒绝，这是 fail-closed 设计，不是 bug）。

一键部署后页面空白或显示 "Hello World" 时，依次检查：`DB` 的 D1 绑定是否存在、
两个 Durable Objects 绑定是否齐全、兼容性标志是否包含
`assets_navigation_prefer_worker`；仍异常时用 Quick Edit 核对线上代码是否为
`src/worker.js` 的最新内容。

### 命令行部署

```bash
git clone https://github.com/kuangdash/kui-worker.git
cd kui-worker
npm install
npx wrangler login
npx wrangler d1 create kui-worker   # 把返回的 database_id 填进 wrangler.jsonc
npx wrangler deploy
```

`wrangler.jsonc` 里的 `database_id` 默认是占位符
（`REPLACE_WITH_YOUR_D1_DATABASE_ID`），不填真实 ID 时部署会直接报错，这是故意的：
不要把任何人的真实 D1 ID 提交到公开仓库。使用已有 D1 时填其 ID，或在 Dashboard 的
Worker **Settings → Bindings** 中把 `DB` 重绑到目标数据库后重新部署（绑定名 `DB`
是固定的，改名会导致后端无法访问数据库）。

本地预览：`npm run dev`。

### 自定义域名

在 Worker 的 **Settings → Domains & Routes → Add** 中绑定域名或子域名后即可使用。

## 配置

### Secret（必填，fail-closed）

仓库不包含任何密码。以下 Secret 未设置时，对应功能直接拒绝服务：

```bash
npx wrangler secret put ADMIN_PASSWORD      # 面板管理员密码（强密码）
npx wrangler secret put PROXY_USER          # 住宅 SOCKS5 用户名
npx wrangler secret put PROXY_PASS          # 住宅 SOCKS5 密码（与 ADMIN_PASSWORD 不同值）
```

也可以在 Dashboard → Worker → **Settings → Variables and Secrets** 中添加后重新部署。
**永远不要把密码写进 `wrangler.jsonc` 的 `vars` 或提交到 git。**

预设登录信息：用户名 `admin`（可用变量 `ADMIN_USERNAME` 修改），
密码为上面设置的 `ADMIN_PASSWORD`。

### Secret / 变量（可选）

| 名称 | 作用 |
|---|---|
| `FRP_AGENT_PASSWORD` | **推荐设置**：住宅 Agent 专用口令。设置后 Agent 面只认它，管理员密码不下发到 VPS；未设置时回退 `ADMIN_PASSWORD` |
| `PROXY_PORT` | 住宅 SOCKS5 默认监听端口（默认 7920，可在面板住宅页修改） |
| `TG_BOT_TOKEN` / `TG_CHAT_ID` | Telegram 离线告警的 Bot Token 与会话 ID |
| `TG_WEBHOOK_SECRET` | Telegram Webhook 校验密钥 |
| `CRON_SECRET` | 外部调用离线检查接口时的 Bearer 密钥 |
| `ADMIN_USERNAME`（vars） | 管理员用户名，默认 `admin` |

### 会话吊销

轮换 `ADMIN_PASSWORD` 后，建议调用一次吊销全部会话，防止旧密码签发的 token 继续有效：

```bash
curl -X DELETE https://<你的域名>/api/sessions -H "Authorization: Bearer <登录token>"
```

## VPS 接入

1. 登录面板，进入**服务器与节点**，添加 VPS 名称与公网 IP；
2. 复制页面生成的 Full Deploy Command，以 `root` 在 VPS 执行
   （部署命令中的 Agent Token 默认掩码显示；也可通过 `KUI_AGENT_TOKEN`
   环境变量传入，避免进入 shell 历史）；
3. 等待 Agent 回连，之后即可创建单个节点或使用"8 合 1"批量部署；
4. 部署第 7 步会尝试安装住宅引擎（见下节），环境不满足时自动跳过，不影响核心功能。

Agent 通过 `/api/agent_update` 拉取自身与组件更新（HMAC 校验完整性），
配置变更经实时通道即时下发。

## 住宅代理说明

- **安装**：VPS 部署第 7 步 `residential-proxy.sh` 用 agent_token 向本 Worker 领取
  安装脚本（`GET /api/proxy/installer`，仅 Agent 可调用），安装脚本在 VPS 本机写入
  `c2.json`（600 权限）并凭 Basic 鉴权拉取引擎
  （`lite_manager.py` / `proxy_server.py`），注册 systemd 服务 `proxy-lite`；
  引擎的心跳与配置拉取对接 `/api/proxy/report` 与 `/api/proxy/agent-config`。
- **凭据模型**：Agent 面 Basic 鉴权的用户名与管理员一致（`ADMIN_USERNAME`），
  口令优先使用 `FRP_AGENT_PASSWORD`（见配置一节）；数据面 SOCKS5 凭据为
  `PROXY_USER` / `PROXY_PASS`。切换口令模式后需逐台重跑住宅安装刷新 `c2.json`。
- **前置要求**：住宅引擎需要 **systemd + apt 系**发行版；不满足时自动跳过，
  KUI 核心功能不受影响。
- **从独立 FRP 迁移**：把 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 设为原 FRP 的
  `WEB_USER` / `WEB_PASS` 同值（或设置 `FRP_AGENT_PASSWORD` 为原 `WEB_PASS`），
  然后逐台重跑住宅安装（c2 地址改为本 Worker 域名）。

## 安全说明

- 密码、Agent Token、订阅 token 的比较全部使用恒定时间比较（先 SHA-256 再比较）；
  登录有失败限流；`workers_dev` 默认关闭。
- `POST /api/logout` 吊销当前会话，`DELETE /api/sessions` 吊销全部会话；
  用户改密码后自动吊销其全部会话。
- VPS 端 HTTP ping 已去除 shell 调用，只接受裸主机名/IP，杜绝命令注入。
- **旧版本安全事件**：早期版本的 `wrangler.jsonc` 曾误提交真实密码。若你部署过
  旧版本：① 立即重设全部 Secret（全新强密码）；② 调用 `DELETE /api/sessions`
  吊销会话；③ 在面板删除重建所有 VPS（轮换 Agent Token）；
  ④ 用 BFG 或 `git filter-repo` 清理仓库历史中的密码后强制推送。

## D1 用量优化

针对 Cloudflare 免费版 D1 的每日读写上限，热路径做了以下削减：

- **Agent 上报**：判重改用 `probe_servers.last_report_id` 单行校验（旧
  `report_receipts` 表退役）；状态类写入 120 秒节流（有流量增量的上报不节流）；
  空闲上报间隔下限 120 秒；
- **鉴权**：Bearer 会话与 Agent Token 走 60 秒隔离内缓存（登出/改密/吊销会话时
  立即失效）；`realtime_url` 读取走 60 秒缓存；`/api/config` 合并重复查询；
- **结构初始化**：`ensureDbSchema` 哨兵快路径，成熟数据库冷启动只需 4 次探测，
  跳过约 60 条 DDL；
- **住宅模块**：全局配置走 30 秒隔离内缓存；单机配置行仅在缺失时才创建
  （`frpEnsureServerConfig` 先读后写）；心跳每 30 秒写一行节点状态；
  大盘快照与订阅生成直接读本 D1 的 `frp_servers`。

## 注意事项

- `DB` 是固定 binding 名称；修改 Worker 变量或绑定后需要重新部署才生效。
- 使用已有 D1 时，确认 `DB` 绑定指向正确数据库；住宅数据与面板数据在同一个库。
- 不要提交任何 Secret、D1 ID、Telegram Token 或代理凭据到 git。
- `workspace-preview.html` 仅用于本地预览，不参与 Worker 静态资源发布。
- `realtime/` 目录是早期独立部署形态的配置；当前版本实时服务已内置于主 Worker，
  正常部署不需要它。

## 开源协议

MIT
