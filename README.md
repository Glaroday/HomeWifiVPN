# mihomo 旁路网关（Bypass Gateway）

把一台 Linux 小主机变成**全局无感代理网关**：局域网终端只要把「网关」和「DNS」指向这台主机，
上网流量就会自动分流——**国内直连、国外走代理**，终端无需安装任何客户端。

附带一个 Web 管理面板（多节点管理 / 一键体检 / 实时速度曲线），
以及一个**终端接入向导页 `/setup`**，用手机打开即可照着图文把其它设备接进来。

---

## 特性

- **透明代理**：TCP 走 nat 表 REDIRECT，UDP 走 mangle 表 TProxy（混合方案，兼容性最好）
- **DNS 接管**：fake-ip 模式，分流的关键；节点域名走独立 DNS，避免 DoH 被墙导致节点全挂
- **多节点管理**：地区筛选（旗标/中文地区名）、延迟 sparkline 小图、收藏星标、一键最优、
  自动选优策略（`fastest` 最快 / `stable` 最稳 / `random` 随机）
- **终端接入向导 `/setup`**：移动端优先的分平台图文步骤（Windows / macOS / iPhone / Android / 路由器），
  手机可看；页面自动获取本机网关参数填充真实 IP / 掩码 / DNS
- **连接成功判定 `/api/connecttest`**：终端自己用浏览器打开就能测「是否已接入网关、分流是否生效」
- **网关信息自动获取 `/api/network`**：自动探测 LAN 网卡、网段、公网出口、建议客户端参数
- **客户端在线列表 `/api/clients`**：IP / MAC / 主机名 / 厂商 / 在线状态 / 是否经网关
- **一键体检 `/api/health`**：9 项系统自检 + 0~100 评分 + 中文修复建议
- **实时速度曲线**：overview 携带近 60 个采样点，面板 canvas 平滑曲线 + 渐变填充
- **动画化界面**：深空玻璃拟态 + 科技渐变 + 微动效（数字滚动 / 呼吸灯 / 环形评分 / ripple）
- **零第三方依赖**：后端纯 Python3 标准库，前端单文件 HTML（无 CDN、无图片字体外链）
- **开机自启**：mihomo、透明代理规则、面板三个 systemd 服务

## 目录结构

```
mihomo-gateway/
├── app/
│   ├── server.py            # 面板后端（Python3 标准库，含全部 API）
│   └── static/
│       ├── index.html       # 管理面板前端（单文件，需登录）
│       └── setup.html       # 终端接入向导页（无需登录，手机可看）
├── scripts/
│   ├── tproxy.sh            # 透明代理规则（TCP REDIRECT + UDP TProxy）
│   └── update-sub.sh        # 订阅拉取与更新（含地区节点数摘要）
├── config/
│   └── config.yaml.tpl      # mihomo 配置模板（__LAN_IP__ 占位）
├── systemd/
│   ├── mihomo.service
│   ├── mihomo-tproxy.service
│   └── mihomo-panel.service
├── docs/
│   └── API-V2.md            # 前后端接口契约（唯一权威约定，只读参考）
├── tests/
│   └── test_api.py          # 后端接口测试
├── install.sh               # 一键安装（幂等）
├── panel.conf               # 面板口令（安装时生成，勿泄露）
└── README.md
```

## 快速开始

前置：已安装 mihomo 二进制到 `/etc/mihomo/mihomo`（arm64/amd64 按架构选择）。

```bash
cd /www/wwwroot/mihomo-gateway
bash install.sh
```

1. **安装**：脚本会安装运行脚本到 `/etc/mihomo`、按需生成 `config.yaml`、生成面板口令、
   装并启动 systemd 服务、放行面板端口。**已存在的配置与口令不会被覆盖。**
2. **打开面板**：浏览器访问 `http://<主机IP>:8090`，输入 `panel.conf` 中的口令。
   在这里管理节点、跑一键体检、看实时速度与在线终端。
3. **教其它设备接入**：打开 `http://<主机IP>:8090/setup`，按页面上的分平台图文步骤配置即可
   （见下「终端接入」）。

## 终端接入（手机 / 电脑）

**推荐**：被接入设备（手机/电脑）直接用浏览器打开向导地址：

```
http://<主机IP>:8090/setup
```

`/setup` 是**给被接入设备看的向导页**，无需登录，移动端优先，内含：

- **接入原理图**：终端 → 网关 → 国内直连 / 国外代理（CSS/SVG 动画）
- **四步接入卡片**：① 改静态 IP ② 网关填 `<主机IP>` ③ DNS 填 `<主机IP>` ④ 打开连接测试页验证
- **分平台 Tab 详细步骤**：Windows 11 / Windows 10 / macOS / iPhone-iPad / Android / 路由器级旁路
- **连接测试区**：一键跳转 `/api/connecttest`，用大号「对/错」判定卡片告诉你是否接入成功
- **常见问题折叠面板**：ping 不通正常、DNS 别填 8.8.8.8、如何恢复 DHCP 等

页面会自动 `fetch /api/network` 填充真实网关 IP / 掩码 / 建议 DNS，无需手抄。

### 连接测试怎么用

在**被接入设备**上打开 `http://<主机IP>:8090/api/connecttest`（或从 `/setup` 页点按钮），
它会站在终端视角逐项检查并给出结论：

- `reach` 连通网关 → `dns` DNS 指向网关 → `gw` 默认网关 → `proxy` 代理链路
- `verdict`：`connected`（已接入，分流生效）/ `partial`（部分通过）/ `not_connected`（未接入）
- 未通过项会在 `hints` 里给出中文排查建议

> 该接口**无需登录**、响应头带 `Access-Control-Allow-Origin: *`，终端设备可直接访问。

### 手动配置（不想看向导时）

把终端的 Wi-Fi 改为静态 IP：

| 项目 | 填写 |
|---|---|
| IP 地址 | 与主机同网段的空闲地址（`/api/network` 会建议 `.100`） |
| 子网掩码 | 255.255.255.0 |
| **网关** | 主机 IP |
| **DNS** | 主机 IP（**不要填 8.8.8.8**，否则分流失效） |

改完重连 Wi-Fi 即可。**ping 外网不通属正常现象**（ICMP 不走代理），以浏览器能否访问为准。

> 恢复直连：终端改回「自动(DHCP)」即可；或主机执行 `bash /etc/mihomo/tproxy.sh stop`。

## 面板功能与接口

所有 `/api/*` 需带请求头 `X-Token: <面板口令>`，**除标注「无登录」者外**。
成功统一 `200 {"ok":true, ...}`；业务失败 `200 {"ok":false,"msg":"..."}`。
完整字段契约见 `docs/API-V2.md`。

| 方法 | 路径 | 登录 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 否 | 校验口令，成功即视为登录 |
| GET | `/api/network` | **否** | 自动探测网关信息：LAN 网卡/IP/网段/掩码、公网出口 IP、建议客户端参数（`suggested_client`）、端口；供 `/setup` 与面板共用 |
| GET | `/api/overview` | 是 | 服务状态、当前节点、节点可用数、连接数、内存、上下行总量与**实时速率**、`speed_history`（≤60 采样点，供速度曲线）、在线终端数、网关/公网 IP |
| GET | `/api/proxies` | 是 | 节点列表（按分组）：类型/延迟/存活/`history`（≤10 次延迟，画 sparkline）/地区 `region`+`region_name`/是否当前；附 `stats`、`favorites`、各 select 组当前选择 |
| POST | `/api/select` | 是 | 切换节点 `{"name":"..."}`（支持 auto 组） |
| POST | `/api/autoselect` | 是 | 自动选优 `{"strategy":"fastest\|stable\|random"}`：最快 / 方差最小且平均<500ms / 存活中随机 |
| POST | `/api/favorite` | 是 | 切换收藏 `{"name":"..."}`，返回新收藏列表；持久化到 `panel_state.json` |
| GET | `/api/nodehistory?name=xxx` | 是 | 返回单个节点的测速历史，便于详情面板 |
| POST | `/api/healthcheck` | 是 | 触发全节点批量测速 |
| GET | `/api/clients` | 是 | 已接入终端列表：IP/MAC/主机名/厂商/`first_seen`/`last_seen`/连接数/在线状态；附 `total`/`online` |
| GET | `/api/health` | 是 | 一键体检：9 项自检（mihomo/tproxy/dns/ipfwd/sub/node/public/disk/load）+ `score`(0~100) + `level`(good/fair/poor) |
| GET | `/api/connecttest` | **否** | 终端视角连接判定：`client_ip`/`gateway_ip`/`via_gateway`/`dns_ok`/`proxy_ok`/`verdict`/`checks[]`/`hints[]`；终端浏览器直接打开即可自测 |
| GET | `/api/subscription` | 是 | 当前订阅（**脱敏**展示） |
| POST | `/api/subscription` | 是 | 保存新订阅并更新 `{"url":"..."}` |
| POST | `/api/subscription/refresh` | 是 | 用现有订阅刷新 |
| POST | `/api/mihomo` | 是 | mihomo 服务控制 `{"action":"start\|stop\|restart"}` |
| POST | `/api/tproxy` | 是 | 透明代理规则控制 `{"action":"start\|stop"}` |
| GET | `/api/logs?lines=150` | 是 | mihomo 运行日志 |

静态页：`GET /` → 面板（需口令）；`GET /setup` → 接入向导（**无登录**）。

## 环境变量

后端支持以下环境变量覆盖缺省值（便于测试/开发，生产环境保持默认即可）：

| 变量 | 缺省 | 说明 |
|---|---|---|
| `MIHOMO_DIR` | `/etc/mihomo` | 运行时目录（配置、订阅、脚本、状态文件所在） |
| `MIHOMO_API` | `http://127.0.0.1:9090` | mihomo 外部控制 API 地址 |
| `PANEL_CONF` | `<项目目录>/panel.conf` | 面板口令文件路径 |
| `MIHOMO_MOCK` | 空 | 置 `1` 启用**内置模拟数据源**：无需 mihomo / systemctl 即可完整演示与测试（节点 24 个，含超时与正弦速度曲线；`/api/connecttest` 可用 `?mock=partial\|not_connected` 演示三种判定态） |

## 常用命令

```bash
systemctl status mihomo mihomo-tproxy mihomo-panel   # 服务状态
bash /etc/mihomo/tproxy.sh status                    # 透明代理规则状态（末尾附机器可读行）
bash /etc/mihomo/tproxy.sh stop|start                # 启停透明代理
bash /etc/mihomo/update-sub.sh                       # 手动更新订阅（含地区节点数摘要）
journalctl -u mihomo -f                              # 实时日志
```

`tproxy.sh status` 末尾会输出机器可读行，便于面板后端解析（后端已做容错）：

```
TPROXY_STATE=on            # nat 与 mangle 规则都在且含 PREROUTING 跳转才 on
TPROXY_NAT_RULES=12        # nat 表 MIHOMO_REDIR 的规则条数
TPROXY_MANGLE_RULES=12     # mangle 表 MIHOMO 的规则条数
```

## 工作原理

```
终端(网关/DNS 指向主机)
        │
        ├─ TCP ─→ nat PREROUTING ─→ REDIRECT :7892 ─┐
        ├─ UDP ─→ mangle PREROUTING ─→ TProxy :7893 ─┤─→ mihomo ─→ 规则分流
        └─ DNS ─→ 主机 :53 (fake-ip) ────────────────┘        ├─ 国内 → DIRECT
                                                             └─ 国外 → 节点
```

- 只劫持 `eth0` 进来的流量，容器/本机流量自动排除
- 目的为网关自身的流量排除（保证 SSH / 面板 / 站点不被劫持）
- ufw 需放行：局域网 → 53(udp/tcp)、TCP 7892、以及 TProxy 标记包（脚本自动处理）
- 端口约定：mixed `7890` / redir `7892` / tproxy `7893` / 外部控制 `9090` / 面板 `8090`

## 排错

| 现象 | 排查方向 |
|---|---|
| 终端改网关后完全不能上网 | 网关 IP 是否填错；`tproxy.sh status` 看规则是否在；**打开面板「诊断」页一键体检**会自动指出 DNS/IP 转发/规则哪一项没通过 |
| 国外站点打不开、国内正常 | 节点问题：面板测速后切一个可用节点；看 `journalctl -u mihomo` 有无 `dial ... error` |
| 节点全部超时 | 订阅是否有效；`proxy-server-nameserver` 是否配置 |
| 终端流量没进主机 | 终端 IP 与主机是否同网段；是否漏填 DNS |
| 面板打不开 | `systemctl status mihomo-panel`；防火墙是否放行面板端口 |
| 不确定终端是否接入成功 | **在终端上打开 `http://<主机IP>:8090/api/connecttest`** 自测；或看面板「终端」页的在线列表与 `via_gateway` 标记 |
| 体检页报某项 fail | 按体检项 `detail` 与提示修复：如 `ipfwd` → `sysctl -w net.ipv4.ip_forward=1`；`tproxy` → `tproxy.sh start` |

## 安全提示

- 面板以 root 运行且能改网络规则，**请勿暴露到公网**；建议仅局域网使用，或经 Nginx 加 HTTPS + 认证
- `panel.conf` 与 `/etc/mihomo/subscribe_url.txt` 含敏感信息，权限分别设为 600
- 订阅链接在面板中始终脱敏展示，真实值只落本机文件
- `/setup` 与 `/api/network`、`/api/connecttest` **无需登录**即可访问，但只暴露网络拓扑信息，
  **不含订阅链接、面板口令等敏感内容**；若担心信息泄露，可仅在局域网内使用面板端口
