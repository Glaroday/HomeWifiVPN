# API-V2 契约（前后端并行开发的唯一约定）

本文件是**唯一权威接口约定**。后端 `app/server.py` 与前端 `app/static/index.html` 必须严格按此实现。
两方并行开发、互不读对方代码，只读本文件。

## 0. 全局约定

- 后端：纯 Python3 标准库，无第三方依赖。路径常量逻辑保持兼容（`/etc/mihomo`、`panel.conf`）。
- 所有 `/api/*`（除 `/api/login` 外）需请求头 `X-Token: <token>`，未授权返回 `401 {"ok":false,"msg":"未授权，请先登录"}`。
- 成功响应统一 `200 {"ok":true, ...}`；业务失败 `200 {"ok":false,"msg":"中文提示"}`；未知路由 `404 {"ok":false,"msg":"not found"}`。
- 时间戳一律 **Unix 秒**（int）。字节单位一律 **bytes**（int）。
- 新增静态页路由：`GET /setup` 返回 `app/static/setup.html`（供手机/电脑无登录查看装机向导，见 §6）。

### 后端环境变量（测试/开发可覆盖，缺省保持生产路径）

| 变量 | 缺省 | 说明 |
|---|---|---|
| `MIHOMO_DIR` | `/etc/mihomo` | 运行时目录 |
| `MIHOMO_API` | `http://127.0.0.1:9090` | mihomo 外部控制 API |
| `PANEL_CONF` | `<project>/panel.conf` | 面板口令文件 |
| `MIHOMO_MOCK` | 空 | 置 `1` 时启用**内置模拟数据源**（无 mihomo、无 systemctl 环境可完整演示/测试，见 §8） |

---

## 1. 网关信息自动获取

### `GET /api/network`

自动探测本机网关信息，前端据此生成装机向导与接入参数。

```json
{
  "ok": true,
  "data": {
    "lan_if": "eth0",
    "lan_ip": "192.168.1.10",
    "lan_cidr": "192.168.1.10/24",
    "netmask": "255.255.255.0",
    "network": "192.168.1.0",
    "prefix": 24,
    "public_ip": "203.0.113.5",
    "gateway_mac": "aa:bb:cc:dd:ee:ff",
    "dns_listen": "192.168.1.10:53",
    "redir_port": 7892,
    "tproxy_port": 7893,
    "mixed_port": 7890,
    "panel_port": 8090,
    "suggested_client": {
      "ip": "192.168.1.100",
      "netmask": "255.255.255.0",
      "gateway": "192.168.1.10",
      "dns": "192.168.1.10"
    },
    "interfaces": [
      {"name": "eth0", "ip": "192.168.1.10", "cidr": "192.168.1.10/24", "up": true}
    ],
    "dhcp_server": true,
    "captured_at": 1760000000
  }
}
```

字段说明：
- `netmask` 由 prefix 换算；`suggested_client.ip` 取本网段 `.100`（避开常见 DHCP 池起点与网关本机）。
- `public_ip` 探测失败时为 `""`，不得报错（超时 3s，结果缓存 10 分钟）。
- `dhcp_server`：本机是否在跑 dnsmasq/udhcpd 等（探测不到则 false）。

---

## 2. 连接成功判定（终端用户视角）

### `GET /api/connecttest`（**无需登录**，供终端设备浏览器直接访问）

终端打开 `http://<网关IP>:8090/api/connecttest` 即可判断自己是否已接入网关。响应头 `Access-Control-Allow-Origin: *`。

```json
{
  "ok": true,
  "data": {
    "client_ip": "192.168.1.23",
    "client_mac": "11:22:33:44:55:66",
    "gateway_ip": "192.168.1.10",
    "via_gateway": true,
    "dns_ok": true,
    "proxy_ok": true,
    "verdict": "connected",
    "verdict_text": "已接入网关，分流代理生效",
    "checks": [
      {"key": "reach", "name": "连通网关", "pass": true,  "detail": "HTTP 可达，说明网络层通"},
      {"key": "dns",   "name": "DNS 指向网关", "pass": true, "detail": "解析走网关 53 端口"},
      {"key": "gw",    "name": "默认网关", "pass": true,  "detail": "流量经网关转发"},
      {"key": "proxy", "name": "代理链路", "pass": true,  "detail": "外网出口 IP 与网关出口一致"}
    ],
    "hints": []
  }
}
```

判定逻辑（后端实现，尽力而为，探测不到的项 `pass` 置 false 并在 `hints` 给出中文排查建议）：
1. `reach`：请求到达面板即 true。
2. `dns`：对该来源 IP 的 53 端口连接计数（`/proc/net/nf_conntrack` 或 `ss`）>0，或来源 IP 落在本网段且 5 分钟内有 DNS 查询；mock 模式下看请求头 `X-Client-Dns` 或直接 true。
3. `gw`：来源 IP 与网关同网段且非网关自身；若无法判定（如远程访问），`pass=false` + hint「请确认终端网关已指向 " + lan_ip + "」。
4. `proxy`：取网关本机出口 IP（`public_ip`），与该终端经代理后的出口一致 → 用 `proxy_ok`；mock 模式 true。
- `verdict` 枚举：`connected` | `partial` | `not_connected`。
- `hints`：string[]，中文。

### `GET /api/clients`（需登录）——面板端查看已接入终端

```json
{
  "ok": true,
  "data": {
    "clients": [
      {
        "ip": "192.168.1.23",
        "mac": "11:22:33:44:55:66",
        "hostname": "iPhone-of-Tom",
        "vendor": "Apple",
        "first_seen": 1759990000,
        "last_seen": 1760000000,
        "conn_count": 12,
        "status": "online",
        "via_gateway": true
      }
    ],
    "total": 4,
    "online": 3
  }
}
```

- 数据来源：`ip neigh show` + `nf_conntrack`/`ss -tnu` 聚合去重；保留最近 24h 见过的客户端（内存环形缓存 ≥500 条）。
- `status` 枚举：`online`（60s 内活跃）| `idle` | `offline`。

---

## 3. 多节点管理（升级版）

### `GET /api/proxies`

```json
{
  "ok": true,
  "data": {
    "current": "香港IEPL-01",
    "groups": [
      {
        "name": "sub",
        "label": "订阅节点",
        "nodes": [
          {
            "name": "香港IEPL-01",
            "type": "ss",
            "udp": true,
            "delay": 128,
            "alive": true,
            "history": [130, 145, 128],
            "region": "HK",
            "region_name": "香港",
            "now": true,
            "last_used": 1759990000
          }
        ]
      }
    ],
    "stats": {"total": 24, "alive": 18, "timeout": 6, "best": "香港IEPL-01", "avg_delay": 220},
    "favorites": ["香港IEPL-01"],
    "selected_in_group": {"PROXY": "香港IEPL-01"},
    "captured_at": 1760000000
  }
}
```

- `region` 从节点名正则识别（HK/JP/TW/US/SG/KR/DE/UK/OTHER），`region_name` 为中文；识别不出用 `OTHER`/`其他`。
- `history` 为最近 ≤10 次测速延迟（0 表示超时），供前端画 sparkline。
- `favorites` 持久化到 `MIHOMO_DIR/panel_state.json`（后端自管），支持 `POST /api/favorite {"name":"..."}` 切换收藏（返回新列表）。
- 其余分组（如手动 proxies）也放进 `groups`，`group.name` 用 mihomo 分组/提供者名。

### `POST /api/select` `{"name":"..."}`（保持兼容，增加 auto 组支持）
### `POST /api/healthcheck`（保持兼容）——批量测速
### `POST /api/autoselect` `{"strategy":"fastest|stable|random"}` → 自动选最优节点

```json
{"ok": true, "msg": "已自动切换到 香港IEPL-01（延迟 128ms）", "data": {"name": "香港IEPL-01", "delay": 128}}
```
- `fastest`：延迟最小且 alive；`stable`：history 方差最小且平均延迟 < 500；`random`：alive 中随机。

### `GET /api/nodehistory?name=xxx`（可选，返回单节点历史，便于详情面板）

---

## 4. 体检 / 诊断

### `GET /api/health`（需登录）——系统自检，前端做「一键体检」动画

```json
{
  "ok": true,
  "data": {
    "score": 86,
    "level": "good",
    "checks": [
      {"key": "mihomo",    "name": "mihomo 服务",   "status": "pass", "detail": "运行中 v1.19.0"},
      {"key": "tproxy",    "name": "透明代理规则",   "status": "pass", "detail": "nat/mangle 规则已加载"},
      {"key": "dns",       "name": "DNS 服务",      "status": "pass", "detail": "监听 192.168.1.10:53"},
      {"key": "ipfwd",     "name": "IP 转发",       "status": "pass", "detail": "net.ipv4.ip_forward=1"},
      {"key": "sub",       "name": "订阅",          "status": "warn", "detail": "订阅已配置但 6 个节点超时"},
      {"key": "node",      "name": "当前节点",       "status": "pass", "detail": "香港IEPL-01 延迟 128ms"},
      {"key": "public",    "name": "公网出口",       "status": "pass", "detail": "出口 IP 203.0.113.5"},
      {"key": "disk",      "name": "磁盘空间",       "status": "pass", "detail": "剩余 12.3 GB"},
      {"key": "load",      "name": "系统负载",       "status": "pass", "detail": "load1 0.12"}
    ],
    "captured_at": 1760000000
  }
}
```

- `status` 枚举：`pass|warn|fail`。`level` 枚举：`good|fair|poor`（由 fail/warn 数量推导：fail≥1→poor，warn≥3→fair，否则 good）。
- `score` = 100 - fail*25 - warn*8，clamp 0..100。

---

## 5. 流量 / 连接概览（升级 overview）

### `GET /api/overview`（保持兼容 + 新增字段）

```json
{
  "ok": true,
  "data": {
    "mihomo": true, "tproxy": true,
    "version": "v1.19.0",
    "current": "香港IEPL-01",
    "nodes_total": 24, "nodes_alive": 18,
    "sub_configured": true,
    "error": "",
    "uptime_sec": 86400,
    "conns": 42,
    "mem_mb": 128.5,
    "down_total": 1073741824, "up_total": 268435456,
    "down_speed": 1048576, "up_speed": 131072,
    "speed_history": [{"t": 1759999940, "down": 524288, "up": 65536}, {"t": 1759999950, "down": 1048576, "up": 131072}],
    "clients_online": 3,
    "lan_ip": "192.168.1.10",
    "public_ip": "203.0.113.5",
    "captured_at": 1760000000
  }
}
```

- `speed_history`：最近 ≤60 个采样点（每 5s 一采，从 mihomo `/connections` 的 up/down 累计差分算速率；mock 模式模拟正弦波动）。
- `mem_mb`：mihomo 进程 RSS（MB，float，取不到为 0）。

---

## 6. 装机向导（教用户在别的设备上配置网关）

### `GET /setup`（**无需登录**，静态 HTML `app/static/setup.html`）

移动端优先的**分平台图文向导**，页面自行 fetch `GET /api/network`（同样无需登录，见 §7）填充真实网关 IP/DNS/掩码。内容包含：

1. **接入原理图**（纯 CSS/SVG 动画：终端 → 网关 → 国内直连/国外代理）
2. **四步接入卡片**：① 改静态 IP ② 网关填 `<lan_ip>` ③ DNS 填 `<lan_ip>` ④ 打开连接测试页验证
3. **分平台 Tab 详细步骤**：Windows 11 / Windows 10 / macOS / iPhone-iPad / Android / 路由器级旁路（可选高级）
4. **连接测试区**：按钮跳 `GET /api/connecttest` 结果渲染成大号 对/错 判定卡片
5. **常见问题折叠面板**（ping 不通正常、DNS 别填 8.8.8.8、恢复 DHCP 等）

### `GET /api/network`（**无需登录**，供 setup.html 与登录后面板共用；仅含网络拓扑信息，不含订阅/口令）

未登录访问 `/api/network` 允许（本页信息本身无敏感 token）；其余 `/api/*` 仍需登录。

---

## 7. 订阅 / 服务控制（保持兼容）

- `POST /api/login`、`GET/POST /api/subscription`、`POST /api/subscription/refresh`、`POST /api/mihomo`、`POST /api/tproxy`、`GET /api/logs?lines=150` 保持现契约不变。
- `GET /api/logs` 响应仍为 `{"ok":true,"data":{"logs":"..."}}`。

---

## 8. Mock 模式（`MIHOMO_MOCK=1`）

后端在 mock 下：
- 所有 API 返回上述完整结构的**确定性假数据**（节点 24 个：HK×6/JP×5/TW×4/US×4/SG×3/KR×2，延迟 30~400ms 稳定伪随机，部分超时）。
- `select`/`autoselect`/`favorite`/`subscription` 等写操作返回成功并更新内存状态，不执行 systemctl。
- `/api/connecttest` 返回 `connected`（或可通过 query `?mock=partial|not_connected` 演示三种判定态）。
- 速度历史用正弦函数模拟，便于前端图表展示。

---

## 9. 前端 UI 要求（index.html 重写，单文件、零外部依赖）

设计基调：**深空玻璃拟态 + 科技渐变 + 微动效**，中文界面。

1. **登录页**：渐变光晕背景 + 玻璃卡片 + 输入框聚焦发光 + 回车登录 + 失败抖动动画。
2. **主界面布局**：顶部导航（仪表盘 / 节点 / 终端 / 诊断 / 向导 / 日志 / 订阅）+ 内容区路由切换（纯 hash，无刷新，切换带淡入位移动画）。
3. **仪表盘**：状态卡片（mihomo/透明代理/当前节点/在线终端）带数字滚动动画；速度曲线 canvas 实时图（平滑曲线 + 渐变填充 + 网格线，5s 自动刷新）；出口 IP/网关信息卡。
4. **节点页**：地区旗标/emoji + 延迟 sparkline 小图 + 延迟色阶 + 搜索 + 地区筛选 chips + 收藏星标 + 「一键最优」按钮 + 批量测速进度条动画 + 当前节点高亮呼吸灯。
5. **终端页**：客户端卡片（IP/MAC/主机名/厂商/在线状态呼吸点/是否经网关），一键「复制接入参数」，链接到 `/setup`。
6. **诊断页**：一键体检按钮 → 环形分数动画 + 各检查项逐条出现（stagger）+ pass/warn/fail 图标动效 + 修复建议。
7. **向导页**：内嵌或 iframe 引 `/setup` 同款内容（可直接链接到 `/setup` 新窗口打开）。
8. **日志页**：等宽字体 + 自动滚动开关 + 刷新。
9. **全局**：Toast 通知（成功/失败色）、按钮 ripple、卡片 hover 抬升、骨架屏加载、深色主题（固定深色即可）、响应式（手机可用）、`prefers-reduced-motion` 降级。
10. **禁止**：外部 CDN、图片文件、字体文件；全部用 CSS/SVG/Canvas 内联。

---

## 10. 文件所有权（并行开发互不越界）

| 子任务 | 允许修改的文件 | 禁止触碰 |
|---|---|---|
| 后端 | `app/server.py` | 其余一切 |
| 前端 | `app/static/index.html`、`app/static/setup.html`（新建） | 其余一切 |
| 脚本文档 | `README.md`、`install.sh`、`scripts/*.sh`、`systemd/*`、`config/*`、`docs/*` | `app/*` |

脚本文档任务具体要求：
- `install.sh`：部署新增的 `setup.html`（随 static 目录走即可，确认 nginx/端口无需改动）、生成口令时打印 `setup` 向导地址；保持幂等。
- `README.md`：按新功能重写（多节点管理/一键体检/终端接入向导/连接测试/新 API 表），含 `/setup`、`/api/connecttest`、`/api/network`、`/api/health`、`/api/autoselect` 等新条目。
- `scripts/tproxy.sh`：`status` 命令追加机器可读输出行 `TPROXY_STATE=on|off`，便于后端解析（后端可容错）。
- `config/config.yaml.tpl`：如需要，确保 `external-controller`、ports 与契约一致（已一致则不动）。
