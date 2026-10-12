#!/bin/bash
# ============================================================
# mihomo 透明代理规则 —— 旁路网关核心
#   TCP: nat 表 REDIRECT  -> redir-port (7892)   兼容性最好
#   UDP: mangle 表 TProxy -> tproxy-port (7893) + 策略路由
# 用法: tproxy.sh start|stop|status
# 前提: mihomo 已运行（systemctl start mihomo）
# ============================================================
set -e

REDIR_PORT=7892
TP_PORT=7893
MARK=1
TABLE=100
LAN_IF=eth0
UFW_BEFORE=/etc/ufw/before.rules

EXCLUDE_CIDRS="0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"

get_lan_ip()   { ip -4 addr show "$LAN_IF" | grep -oP 'inet \K[\d.]+' | head -1; }
get_lan_cidr() { ip -4 addr show "$LAN_IF" | grep -oP 'inet \K[\d./]+' | head -1; }

allow_ufw() {
  local cidr; cidr=$(get_lan_cidr)
  # 局域网终端到盒子的 DNS
  ufw allow from "$cidr" to any port 53 proto udp >/dev/null 2>&1 || true
  ufw allow from "$cidr" to any port 53 proto tcp >/dev/null 2>&1 || true
  # 劫持后的包放行：UDP(TProxy) 带 mark 1；TCP(REDIRECT) 目的为 redir 端口
  if [ -f "$UFW_BEFORE" ] && ! grep -q "mihomo-tproxy" "$UFW_BEFORE"; then
    sed -i "/^-A ufw-before-input -i lo -j ACCEPT/a # mihomo-tproxy: allow hijacked packets to reach local mihomo socket\n-A ufw-before-input -m mark --mark 1 -j ACCEPT\n-A ufw-before-input -p tcp --dport $REDIR_PORT -j ACCEPT" "$UFW_BEFORE"
    ufw reload >/dev/null 2>&1 || true
  fi
}

start() {
  if ! systemctl is-active --quiet mihomo; then
    echo "❌ mihomo 未运行，请先: systemctl start mihomo"; exit 1
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  local lan_ip; lan_ip=$(get_lan_ip)

  # ---------- TCP: nat 表 REDIRECT ----------
  iptables -t nat -N MIHOMO_REDIR 2>/dev/null || true
  iptables -t nat -F MIHOMO_REDIR
  # 只处理局域网网卡进来的流量（排除 docker0/br-* 等容器与内部流量）
  iptables -t nat -A MIHOMO_REDIR ! -i "$LAN_IF" -j RETURN
  for cidr in $EXCLUDE_CIDRS; do
    iptables -t nat -A MIHOMO_REDIR -d "$cidr" -j RETURN
  done
  # 关键：排除目的为盒子自身的流量（SSH/宝塔面板等）
  iptables -t nat -A MIHOMO_REDIR -d "$lan_ip" -j RETURN
  iptables -t nat -A MIHOMO_REDIR -p tcp -j REDIRECT --to-ports $REDIR_PORT
  iptables -t nat -C PREROUTING -j MIHOMO_REDIR 2>/dev/null || iptables -t nat -I PREROUTING 1 -j MIHOMO_REDIR

  # ---------- UDP: mangle 表 TProxy + 策略路由 ----------
  ip rule add fwmark $MARK table $TABLE 2>/dev/null || true
  ip route replace local default dev lo table $TABLE
  iptables -t mangle -N MIHOMO 2>/dev/null || true
  iptables -t mangle -F MIHOMO
  # 只处理局域网网卡进来的流量
  iptables -t mangle -A MIHOMO ! -i "$LAN_IF" -j RETURN
  for cidr in $EXCLUDE_CIDRS; do
    iptables -t mangle -A MIHOMO -d "$cidr" -j RETURN
  done
  iptables -t mangle -A MIHOMO -d "$lan_ip" -j RETURN
  iptables -t mangle -A MIHOMO -p udp -j TPROXY --on-port $TP_PORT --tproxy-mark $MARK
  iptables -t mangle -C PREROUTING -j MIHOMO 2>/dev/null || iptables -t mangle -I PREROUTING 1 -j MIHOMO

  allow_ufw
  echo "✅ 透明代理已启用（TCP: REDIRECT $REDIR_PORT / UDP: TProxy $TP_PORT）"
  echo "TPROXY_STATE=on"
}

stop() {
  iptables -t nat -D PREROUTING -j MIHOMO_REDIR 2>/dev/null || true
  iptables -t nat -F MIHOMO_REDIR 2>/dev/null || true
  iptables -t nat -X MIHOMO_REDIR 2>/dev/null || true
  iptables -t mangle -D PREROUTING -j MIHOMO 2>/dev/null || true
  iptables -t mangle -F MIHOMO 2>/dev/null || true
  iptables -t mangle -X MIHOMO 2>/dev/null || true
  ip rule del fwmark $MARK table $TABLE 2>/dev/null || true
  ip route flush table $TABLE 2>/dev/null || true
  echo "✅ 透明代理已停用（终端网关改回路由器即可恢复直连）"
  echo "TPROXY_STATE=off"
}

status() {
  echo "--- nat MIHOMO_REDIR（TCP）---"
  iptables -t nat -S MIHOMO_REDIR 2>/dev/null || echo "(未启用)"
  echo "--- mangle MIHOMO（UDP）---"
  iptables -t mangle -S MIHOMO 2>/dev/null || echo "(未启用)"
  echo "--- 策略路由 ---"
  ip rule show | grep "fwmark 0x1" || echo "(未启用)"

  # ---- 机器可读行（供面板后端解析，勿改格式）----
  local nat_rules mangle_rules nat_jump mangle_jump state
  nat_rules=$(iptables -t nat -S MIHOMO_REDIR 2>/dev/null | grep -c '^-A' || true)
  mangle_rules=$(iptables -t mangle -S MIHOMO 2>/dev/null | grep -c '^-A' || true)
  nat_jump=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -c 'MIHOMO_REDIR' || true)
  mangle_jump=$(iptables -t mangle -S PREROUTING 2>/dev/null | grep -c 'MIHOMO' || true)
  if [ "${nat_rules:-0}" -gt 0 ] && [ "${mangle_rules:-0}" -gt 0 ] \
     && [ "${nat_jump:-0}" -gt 0 ] && [ "${mangle_jump:-0}" -gt 0 ]; then
    state=on
  else
    state=off
  fi
  echo "TPROXY_STATE=$state"
  echo "TPROXY_NAT_RULES=${nat_rules:-0}"
  echo "TPROXY_MANGLE_RULES=${mangle_rules:-0}"
}

case "$1" in
  start)  start  ;;
  stop)   stop   ;;
  status) status ;;
  *) echo "用法: $0 start|stop|status"; exit 1 ;;
esac
