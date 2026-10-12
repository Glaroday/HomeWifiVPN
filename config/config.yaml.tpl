# ============================================================
# mihomo (Clash.Meta) 旁路网关配置模板
# 安装时由 install.sh 替换 __LAN_IP__ 后写入 /etc/mihomo/config.yaml
# ============================================================

# ---------- 基础 ----------
mixed-port: 7890            # HTTP/SOCKS5 混合端口（本机或内网显式使用）
allow-lan: true             # 透明代理必须开启，否则不处理局域网来源流量
bind-address: '*'
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090   # 仅本机可访问的 API
unified-delay: true
tcp-concurrent: true
store-selected: true        # 记住手动切换的节点，重启不丢

# geo 数据库下载走镜像（国内直连 github 易失败）
geodata-mode: false
geox-url:
  geoip: "https://ghfast.top/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
  geosite: "https://ghfast.top/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
  mmdb: "https://ghfast.top/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"

# ---------- TUN 模式（Windows 整机透明代理；默认关闭）----------
# 开启后会接管本机全部流量与 DNS，需要管理员权限 + 同目录 wintun.dll。
# 注意：开启前请确认没有其他代理软件（如 Clash Verge）占用 7890/9090/53 端口，
#       否则核心会启动失败并可能造成短暂断网。可在面板「TUN 模式」卡片一键开关。
tun:
  enable: false
  stack: gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53

# ---------- 透明代理入口 ----------
redir-port: 7892            # TCP 透明代理（REDIRECT，兼容性最好）
tproxy-port: 7893           # UDP 透明代理（TProxy）

# ---------- DNS：旁路网关分流的关键，由 Clash 接管 ----------
dns:
  enable: true
  listen: __LAN_IP__:53     # 只绑局域网 IP，避开 systemd-resolved 的 127.0.0.53
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - '*.arpa'
    - 'time.*.com'
    - 'ntp.*.com'
    - '+.market.xiaomi.com'
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  # 关键：节点服务器域名专用解析（不走 fallback，避免 DoH 被墙导致节点全挂）
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

# ---------- 节点：由订阅文件 providers/sub.yaml 提供 ----------
proxies: []

proxy-providers:
  sub:
    type: file
    path: ./providers/sub.yaml
    health-check:
      enable: true
      interval: 600
      lazy: true
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: PROXY
    type: select
    use:
      - sub
    proxies:
      - AUTO                # 可选：url-test 自动选优组（见下方注释）
      - DIRECT              # 无可用节点时手动切到 DIRECT 兜底

  # ---- 可选增强：AUTO 自动选优组（url-test）----
  # 说明：面板的「一键最优」默认走后端 /api/autoselect，无需依赖本组；
  #       本组额外提供一个由 mihomo 自行维护的延迟最小节点，便于显式代理或其它客户端引用。
  #       它【不改变】PROXY(select) 的语义：PROXY 仍由用户手动切换，只是多了一个可选项 AUTO。
  - name: AUTO
    type: url-test
    use:
      - sub
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50

# ---------- 分流规则 ----------
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
