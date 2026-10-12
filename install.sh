#!/bin/bash
# ============================================================
# mihomo 旁路网关 —— 一键安装脚本
# 适用: Debian/Armbian (root)
# 幂等: 已存在的配置/口令不会被覆盖
# ============================================================
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
LAN_IF="${LAN_IF:-eth0}"
PANEL_PORT="${PANEL_PORT:-8090}"

[ "$(id -u)" = "0" ] || { echo "❌ 请用 root 运行"; exit 1; }

echo "==> 1/6 检查与自动安装 mihomo 二进制"
mkdir -p /etc/mihomo
if [ ! -x /etc/mihomo/mihomo ]; then
  ARCH_RAW="$(uname -m)"
  case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7*) ARCH="armv7" ;;
    *) ARCH="amd64" ;;
  esac
  VER="v1.19.21"
  ASSET="mihomo-linux-${ARCH}-${VER}.gz"
  BASE_URL="https://github.com/MetaCubeX/mihomo/releases/download/${VER}/${ASSET}"
  echo "    未检测到 /etc/mihomo/mihomo，正在为 linux/${ARCH} 自动从镜像源下载 (${ASSET})..."
  for PREFIX in "https://ghfast.top/" "https://gh-proxy.com/" "https://github.moeyy.xyz/" ""; do
    DL="${PREFIX}${BASE_URL}"
    echo "    尝试镜像: ${DL}"
    if curl -fsSL --connect-timeout 12 -m 90 -o /tmp/mihomo.gz "$DL" 2>/dev/null; then
      if gunzip -c /tmp/mihomo.gz > /etc/mihomo/mihomo 2>/dev/null; then
        chmod 755 /etc/mihomo/mihomo
        rm -f /tmp/mihomo.gz
        break
      fi
    fi
  done
fi
if [ ! -x /etc/mihomo/mihomo ]; then
  echo "    ⚠️ 脚本自动下载未完成，你可在面板启动后直接在网页端选择镜像源一键安装 mihomo 核心"
else
  echo "    OK: $(/etc/mihomo/mihomo -v 2>/dev/null | head -1)"
fi

echo "==> 2/6 安装运行脚本到 /etc/mihomo"
install -m 755 "$ROOT/scripts/tproxy.sh"    /etc/mihomo/tproxy.sh
install -m 755 "$ROOT/scripts/update-sub.sh" /etc/mihomo/update-sub.sh
mkdir -p /etc/mihomo/providers
[ -f /etc/mihomo/providers/sub.yaml ] || printf 'proxies: []\n' > /etc/mihomo/providers/sub.yaml
[ -f /etc/mihomo/subscribe_url.txt ] || touch /etc/mihomo/subscribe_url.txt

# 面板静态资源由后端直接从项目目录提供（server.py 的 STATIC_DIR = app/static），
# 因此这里【不复制】app/，只确认文件齐全；systemd 的 WorkingDirectory 指向项目目录即可。
if [ -f "$ROOT/app/static/index.html" ]; then
  echo "    OK: app/static 就绪（$(find "$ROOT/app/static" -type f | wc -l) 个文件）"
else
  echo "    ⚠️ 未找到 $ROOT/app/static/index.html，面板页面可能无法打开"
fi

echo "==> 3/6 生成 mihomo 配置（已存在则保留）"
if [ ! -f /etc/mihomo/config.yaml ]; then
  LAN_IP=$(ip -4 addr show "$LAN_IF" | grep -oP 'inet \K[\d.]+' | head -1)
  [ -n "$LAN_IP" ] || { echo "❌ 未取到 $LAN_IF 的 IP"; exit 1; }
  sed "s/__LAN_IP__/$LAN_IP/" "$ROOT/config/config.yaml.tpl" > /etc/mihomo/config.yaml
  echo "    已生成 config.yaml (LAN_IP=$LAN_IP)"
else
  echo "    已存在 /etc/mihomo/config.yaml，跳过"
fi

echo "==> 4/6 生成面板配置 panel.conf"
if [ ! -f "$ROOT/panel.conf" ]; then
  TOKEN=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
  # 兜底：极端情况下随机口令取空时，给一个可用临时口令并提示，避免写出空 token
  if [ -z "$TOKEN" ]; then
    echo "    ⚠️ 随机口令生成失败，已写入临时口令；请手动修改 $ROOT/panel.conf 的 token="
    TOKEN="panel-$(date +%s)"
  fi
  cat > "$ROOT/panel.conf" <<EOF
# mihomo 网关面板配置
port=$PANEL_PORT
token=$TOKEN
EOF
  chmod 600 "$ROOT/panel.conf"
else
  echo "    已存在 panel.conf，跳过（口令保留）"
fi

echo "==> 5/6 安装并启动 systemd 服务"
install -m 644 "$ROOT/systemd/mihomo.service"         /etc/systemd/system/mihomo.service
install -m 644 "$ROOT/systemd/mihomo-tproxy.service"  /etc/systemd/system/mihomo-tproxy.service
install -m 644 "$ROOT/systemd/mihomo-panel.service"   /etc/systemd/system/mihomo-panel.service
systemctl daemon-reload
systemctl enable --now mihomo
systemctl enable mihomo-tproxy >/dev/null 2>&1 || true
systemctl restart mihomo-tproxy
systemctl enable --now mihomo-panel
systemctl restart mihomo-panel

echo "==> 6/6 放行面板端口（局域网）"
CIDR=$(ip -4 addr show "$LAN_IF" | grep -oP 'inet \K[\d./]+' | head -1)
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  # 面板端口
  ufw allow from "$CIDR" to any port "$PANEL_PORT" proto tcp >/dev/null 2>&1 || true
  # 透明代理所需：DNS 53(udp/tcp) 与 TCP REDIRECT 7892（tproxy.sh 也会放行，这里再兜一次）
  ufw allow from "$CIDR" to any port 53 proto udp >/dev/null 2>&1 || true
  ufw allow from "$CIDR" to any port 53 proto tcp >/dev/null 2>&1 || true
  ufw allow from "$CIDR" to any port 7892 proto tcp >/dev/null 2>&1 || true
  echo "    已放行：$PANEL_PORT/tcp, 53/udp, 53/tcp, 7892/tcp (from $CIDR)"
fi

IP=$(ip -4 addr show "$LAN_IF" | grep -oP 'inet \K[\d.]+' | head -1)
TOKEN=$(grep -E '^token=' "$ROOT/panel.conf" | cut -d= -f2-)
echo
echo "=================== 安装完成 ==================="
echo " 面板地址 : http://$IP:$PANEL_PORT"
echo " 向导地址 : http://$IP:$PANEL_PORT/setup"
echo " 面板口令 : $TOKEN"
echo " 配置文件 : $ROOT/panel.conf"
echo " 服务状态 : systemctl status mihomo mihomo-tproxy mihomo-panel"
echo "================================================"
echo " 终端(手机/电脑)设置：网关与 DNS 都填 $IP"
echo " 把这台设备的网关与 DNS 都设为 $IP 即可；手机可打开上面的向导地址按步骤配置"
