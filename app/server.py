#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mihomo 旁路网关管理面板 —— 后端服务（全真实数据生产版）
纯 Python3 标准库实现，无第三方依赖，支持 Linux systemd 托管及本机直接运行。

职责：
  - 网关信息真实探测（/api/network：网卡、IP、掩码、默认网关、MAC、公网出口、推荐终端参数）
  - 终端连接真实判定（/api/connecttest、/api/clients：ARP/邻居表 + 活跃连接聚合）
  - 多订阅真实拉取与解析（/api/subscription/*：支持 Clash YAML 与 Base64 链接、多订阅合并去重）
  - 多节点管理与真实测速（/api/proxies、/api/healthcheck、/api/autoselect、/api/favorite）
  - 系统真实体检（/api/health：9 项核心指标实测评分）
  - 流量与服务概览（/api/overview、/api/mihomo、/api/tproxy、/api/logs）
"""
import base64
import collections
from concurrent.futures import ThreadPoolExecutor
import gzip
import io
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ============================================================
# 路径与配置
# ============================================================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(APP_DIR)
STATIC_DIR = os.path.join(APP_DIR, "static")


def _resolve_mihomo_dir():
    """优先使用环境变量 MIHOMO_DIR；Linux 下若 /etc/mihomo 存在则使用，否则使用项目下 data 目录。"""
    env_dir = (os.environ.get("MIHOMO_DIR") or "").strip()
    if env_dir:
        return env_dir
    if os.name != "nt" and (os.path.isdir("/etc/mihomo") or os.access("/etc", os.W_OK)):
        return "/etc/mihomo"
    return os.path.join(PROJECT_DIR, "data")


MIHOMO_DIR = _resolve_mihomo_dir()
MIHOMO_API = (os.environ.get("MIHOMO_API") or "http://127.0.0.1:9090").rstrip("/")
PANEL_CONF = os.environ.get("PANEL_CONF") or os.path.join(PROJECT_DIR, "panel.conf")

MIHOMO_BIN = os.path.join(MIHOMO_DIR, "mihomo.exe" if os.name == "nt" else "mihomo")
CONFIG_FILE = os.path.join(MIHOMO_DIR, "config.yaml")
CONFIG_TPL_FILE = os.path.join(PROJECT_DIR, "config", "config.yaml.tpl")
MIHOMO_LOG_FILE = os.path.join(MIHOMO_DIR, "mihomo.log")
SUB_URL_FILE = os.path.join(MIHOMO_DIR, "subscribe_url.txt")
SUB_FILE = os.path.join(MIHOMO_DIR, "providers", "sub.yaml")
UPDATE_SH = os.path.join(MIHOMO_DIR, "update-sub.sh")
TPROXY_SH = os.path.join(MIHOMO_DIR, "tproxy.sh")
PANEL_STATE_FILE = os.path.join(MIHOMO_DIR, "panel_state.json")
GROUP_NAME = "PROXY"

REDIR_PORT = 7892
TPROXY_PORT = 7893
MIXED_PORT = 7890
GROUP_TYPES = ("Selector", "URLTest", "Fallback", "LoadBalance", "Relay")
SERVER_START_TIME = time.time()


def load_conf():
    """读取面板配置文件 panel.conf，返回 {"port": int, "token": str}。"""
    conf = {"port": "8090", "token": ""}
    try:
        with open(PANEL_CONF, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    except OSError:
        pass
    try:
        conf["port"] = int(conf["port"])
    except (TypeError, ValueError):
        conf["port"] = 8090
    return conf


CONF = load_conf()


# ============================================================
# 基础工具函数
# ============================================================
def mask_url(url):
    """脱敏：隐藏订阅链接中的 token/key/secret/password/uuid 等敏感参数或路径段。"""
    if not url:
        return ""
    masked = re.sub(r"(?i)(token|key|secret|password|passwd|uuid|auth)=[^&#\s]+", r"\1=***", url)
    if masked == url:
        try:
            u = urllib.parse.urlparse(url)
            if len(u.path) > 16:
                masked = "%s://%s%s***" % (u.scheme, u.netloc, u.path[:12])
        except Exception:  # noqa
            pass
    return masked


def run(cmd, timeout=10):
    """执行系统命令，返回 (returncode, output)；任何异常优雅降级。"""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        raw = (p.stdout or b"") + (p.stderr or b"")
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            txt = raw.decode("gbk", errors="replace")
        return p.returncode, txt.strip()
    except subprocess.TimeoutExpired:
        return 124, "命令执行超时"
    except Exception as e:  # noqa
        return 1, str(e)


def mihomo_api(path, method="GET", payload=None, timeout=6):
    """调用 mihomo 外部控制 API。"""
    url = MIHOMO_API + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw": body}


def mihomo_api_safe(path, method="GET", payload=None, timeout=4):
    """安全调用 mihomo API：不可达时返回 None。"""
    try:
        return mihomo_api(path, method=method, payload=payload, timeout=timeout)
    except Exception:  # noqa
        return None


def service_active(name):
    """判断服务是否正在运行（Linux 查 systemctl / 进程，或检测 mihomo API）。"""
    if name == "mihomo":
        if isinstance(mihomo_api_safe("/version", timeout=2), dict):
            return True
    if os.name != "nt":
        rc, out = run("systemctl is-active %s" % name, timeout=5)
        if out.strip() == "active":
            return True
    return False


def _ip2int(ip):
    """点分十进制 IPv4 转 32 位整数。"""
    try:
        return struct.unpack(">I", socket.inet_aton(ip))[0]
    except (OSError, ValueError):
        return None


def netmask_to_prefix(mask):
    """点分十进制子网掩码转前缀长度（如 255.255.255.0 -> 24）。"""
    i = _ip2int(mask)
    if i is None:
        return 24
    return bin(i).count("1")


def prefix_to_netmask(prefix):
    """由前缀长度换算点分十进制掩码。"""
    try:
        prefix = int(prefix)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if 0 < prefix <= 32 else 0
        return socket.inet_ntoa(struct.pack(">I", mask))
    except Exception:  # noqa
        return "255.255.255.0"


def network_addr(ip, prefix):
    """计算网段地址。"""
    i = _ip2int(ip)
    if i is None:
        return ""
    try:
        prefix = int(prefix)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if 0 < prefix <= 32 else 0
        return socket.inet_ntoa(struct.pack(">I", i & mask))
    except Exception:  # noqa
        return ""


def broadcast_addr(network, prefix):
    """计算广播地址。"""
    n = _ip2int(network)
    if n is None:
        return ""
    try:
        prefix = int(prefix)
        host = (1 << (32 - prefix)) - 1 if 0 < prefix <= 32 else 0
        return socket.inet_ntoa(struct.pack(">I", n | host))
    except Exception:  # noqa
        return ""


def is_lan_ip(ip):
    """判断是否为私有局域网单播 IPv4（排除回环、组播、广播）。"""
    i = _ip2int(ip or "")
    if i is None:
        return False
    p = [int(x) for x in ip.split(".")]
    if p[3] in (0, 255):
        return False
    if p[0] == 10:
        return True
    if p[0] == 172 and 16 <= p[1] <= 31:
        return True
    if p[0] == 192 and p[1] == 168:
        return True
    return False


OUI_VENDOR = {
    "00:1C:B3": "Apple", "3C:07:54": "Apple", "A4:83:E7": "Apple", "F0:18:98": "Apple",
    "D0:81:7A": "Apple", "AC:BC:32": "Apple", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "52:54:00": "QEMU/KVM", "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:1B:21": "Intel",
    "3C:97:0E": "Intel", "94:65:9C": "Intel", "F4:F5:D8": "Google", "54:60:09": "Google",
    "B0:BE:76": "TP-Link", "50:C7:BF": "TP-Link", "C4:92:D9": "路由器/网关", "38:2C:4A": "ASUS",
    "2C:56:DC": "ASUS", "64:16:66": "Huawei", "00:E0:FC": "Huawei", "34:CE:00": "Xiaomi",
    "64:CC:2E": "Xiaomi", "78:11:DC": "Xiaomi", "E4:70:B8": "Samsung", "34:AA:8B": "Samsung",
}


def vendor_of(mac):
    """按 MAC OUI 前缀识别设备厂商。"""
    if not mac:
        return "局域网设备"
    norm = mac.replace("-", ":").upper()
    if norm in OUI_VENDOR:
        return OUI_VENDOR[norm[:8]]
    # 本地随机管理 MAC (LAA: 第二位为 2/6/A/E，常见于 iOS/Android 隐私 MAC)
    if len(norm) >= 2 and norm[1] in ("2", "6", "A", "E"):
        return "移动终端 (隐私MAC)"
    return "局域网终端"


REGION_RULES = [
    ("HK", "香港", r"香港|hong\s?kong|\bhk\b|🇭🇰|港"),
    ("JP", "日本", r"日本|japan|\bjp\b|东京|大阪|tokyo|osaka|🇯🇵"),
    ("TW", "台湾", r"台湾|台灣|taiwan|\btw\b|台北|新北|🇹🇼"),
    ("SG", "新加坡", r"新加坡|singapore|\bsg\b|狮城|🇸🇬"),
    ("US", "美国", r"美国|美國|united\s?states|\busa\b|\bus\b|洛杉矶|圣何塞|西雅图|硅谷|纽约|芝加哥|🇺🇸"),
    ("KR", "韩国", r"韩国|韓國|korea|\bkr\b|首尔|seoul|🇰🇷"),
    ("DE", "德国", r"德国|德國|germany|\bde\b|法兰克福|frankfurt|🇩🇪"),
    ("UK", "英国", r"英国|英國|united\s?kingdom|\buk\b|\bgb\b|伦敦|london|🇬🇧"),
]


def detect_region(name):
    """从节点名识别地区码与中文名。"""
    n = (name or "").lower()
    for code, cname, pat in REGION_RULES:
        if re.search(pat, n, re.I):
            return code, cname
    return "OTHER", "其他"


# ============================================================
# 面板持久化状态（收藏、多订阅、解析后的节点缓存）
# ============================================================
_STATE_LOCK = threading.Lock()
_STATE = {
    "favorites": [],
    "subscriptions": [],
    "parsed_nodes": [],
    "selected_node": "",
    "last_used": {},
}
_STATE_LOADED = False


def _load_state():
    """从 PANEL_STATE_FILE 载入持久化状态。"""
    global _STATE_LOADED
    if _STATE_LOADED:
        return
    try:
        with open(PANEL_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _STATE.update(data)
    except Exception:  # noqa
        pass
    for k in ("favorites", "subscriptions", "parsed_nodes"):
        if not isinstance(_STATE.get(k), list):
            _STATE[k] = []
    if not isinstance(_STATE.get("last_used"), dict):
        _STATE["last_used"] = {}
    _STATE_LOADED = True


def _save_state():
    """保存状态到 PANEL_STATE_FILE。"""
    try:
        os.makedirs(MIHOMO_DIR, exist_ok=True)
        with open(PANEL_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(_STATE, f, ensure_ascii=False, indent=2)
        return True
    except Exception:  # noqa
        return False


def get_favorites():
    with _STATE_LOCK:
        _load_state()
        return list(_STATE.get("favorites", []))


def toggle_favorite(name):
    if not name:
        return None
    with _STATE_LOCK:
        _load_state()
        favs = _STATE.setdefault("favorites", [])
        if name in favs:
            favs.remove(name)
        else:
            favs.append(name)
        _save_state()
        return list(favs)


# ============================================================
# 真实网络与终端探测（兼容 Linux 与 Windows 本机）
# ============================================================
def _outbound_lan_ip():
    """通过 UDP 路由探测本机真实出网局域网 IP（不发送任何数据包）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:  # noqa
        return ""


def list_interfaces():
    """枚举本机真实 IPv4 网卡列表。"""
    result = []
    if os.name != "nt":
        up_map = {}
        _, out_link = run("ip -o link show", timeout=5)
        for line in out_link.splitlines():
            m = re.match(r"^\d+:\s+(\S+?)[:@]", line)
            if m:
                up_map[m.group(1)] = ("UP" in line and "DOWN" not in line.split("<")[1].split(">")[0] if "<" in line else False)
        _, out_addr = run("ip -4 -o addr show", timeout=5)
        for line in out_addr.splitlines():
            m = re.search(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
            if not m:
                continue
            name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
            if ip.startswith("127."):
                continue
            result.append({
                "name": name,
                "ip": ip,
                "cidr": "%s/%d" % (ip, prefix),
                "up": bool(up_map.get(name, True)),
            })
    if not result:
        # Windows 或无 ip 命令环境：解析 ipconfig 与出网 socket
        out_ip = _outbound_lan_ip()
        _, out = run("ipconfig", timeout=5)
        cur_name = "LAN"
        cur_ip = ""
        cur_mask = "255.255.255.0"
        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue
            if raw and not raw[0].isspace() and line.endswith(":"):
                cur_name = line[:-1].strip()
                cur_ip = ""
            m_ip = re.search(r"IPv4[^:：]*[:：]\s*([\d.]+)", line, re.I)
            if m_ip:
                cur_ip = m_ip.group(1)
            m_mask = re.search(r"(?:子网掩码|Subnet Mask)[^:：]*[:：]\s*([\d.]+)", line, re.I)
            if m_mask and cur_ip:
                cur_mask = m_mask.group(1)
                pfx = netmask_to_prefix(cur_mask)
                result.append({
                    "name": cur_name,
                    "ip": cur_ip,
                    "cidr": "%s/%d" % (cur_ip, pfx),
                    "up": True,
                })
                cur_ip = ""
        if not result and out_ip:
            result.append({"name": "eth0", "ip": out_ip, "cidr": "%s/24" % out_ip, "up": True})
    return result


def default_route(primary_ip=""):
    """探测本机真实默认路由网关 (gateway_ip, dev)。"""
    if os.name != "nt":
        _, out = run("ip route show default", timeout=5)
        m = re.search(r"default via ([\d.]+)(?:\s+dev\s+(\S+))?", out)
        if m:
            return m.group(1) or "", m.group(2) or ""
    else:
        _, out = run("ipconfig", timeout=5)
        last_ip = ""
        for line in out.splitlines():
            m_ip = re.search(r"IPv4[^:：]*[:：]\s*([\d.]+)", line, re.I)
            if m_ip:
                last_ip = m_ip.group(1)
            m_gw = re.search(r"(?:默认网关|Default Gateway)[^:：]*[:：]\s*([\d.]+)", line, re.I)
            if m_gw and (not primary_ip or last_ip == primary_ip):
                return m_gw.group(1), ""
    if primary_ip and "." in primary_ip:
        return primary_ip.rsplit(".", 1)[0] + ".1", ""
    return "", ""


def gateway_mac(gw_ip):
    """查询指定 IP 的真实 MAC 地址（兼容 ip neigh / arp -a）。"""
    if not gw_ip:
        return ""
    if os.name != "nt":
        _, out = run("ip neigh show %s" % gw_ip, timeout=4)
        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1).lower()
    _, out = run("arp -a", timeout=5)
    for line in out.splitlines():
        if gw_ip in line:
            m = re.search(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", line)
            if m:
                mac = m.group(1).replace("-", ":").lower()
                if mac != "ff:ff:ff:ff:ff:ff":
                    return mac
    return ""


def detect_dhcp_server():
    """探测本机是否开启了 DHCP 服务端。"""
    if os.name != "nt":
        rc, out = run("pgrep -x dnsmasq || pgrep -x udhcpd", timeout=4)
        if rc == 0 and out.strip():
            return True
        _, out = run("ss -lun", timeout=4)
        return bool(re.search(r":67\s", out))
    return False


_PUBLIC_IP_CACHE = {"ip": "", "t": 0.0}


def get_public_ip(force=False):
    """探测本机真实公网出口 IP（超时 3 秒，缓存 10 分钟）。"""
    now = time.time()
    if not force and _PUBLIC_IP_CACHE["ip"] and (now - _PUBLIC_IP_CACHE["t"]) < 600:
        return _PUBLIC_IP_CACHE["ip"]
    ip = ""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                cand = resp.read().decode("utf-8", "replace").strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cand):
                ip = cand
                break
        except Exception:  # noqa
            pass
    _PUBLIC_IP_CACHE["ip"] = ip
    _PUBLIC_IP_CACHE["t"] = now
    return ip


def _suggest_client(network, prefix, gateway, lan_ip):
    """推荐给其他终端填写的同网段空闲静态 IP。"""
    if not network:
        return ""
    base = network.rsplit(".", 1)[0]
    bcast = broadcast_addr(network, prefix)
    for cand in (100, 108, 120, 150, 200):
        ip = "%s.%d" % (base, cand)
        if ip not in (gateway, lan_ip, network, bcast):
            return ip
    return ""


def api_network():
    """§1 真实网关与网络拓扑信息探测。"""
    ifaces = list_interfaces()
    out_ip = _outbound_lan_ip()

    lan_if, lan_ip, prefix = "", "", 24
    for it in ifaces:
        if out_ip and it["ip"] == out_ip:
            lan_if, lan_ip, prefix = it["name"], it["ip"], int(it["cidr"].split("/")[1])
            break
    if not lan_ip:
        for it in ifaces:
            if is_lan_ip(it["ip"]) and not it["name"].lower().startswith(("docker", "br-", "veth", "lo", "vmware", "vethernet")):
                lan_if, lan_ip, prefix = it["name"], it["ip"], int(it["cidr"].split("/")[1])
                break
    if not lan_ip and out_ip:
        lan_if, lan_ip, prefix = "LAN", out_ip, 24

    gw_ip, gw_dev = default_route(lan_ip)
    if gw_dev and not lan_if:
        lan_if = gw_dev
    netmask = prefix_to_netmask(prefix) if lan_ip else "255.255.255.0"
    network = network_addr(lan_ip, prefix) if lan_ip else ""
    gateway = gw_ip or (network.rsplit(".", 1)[0] + ".1" if network else "")

    return {
        "lan_if": lan_if or "eth0",
        "lan_ip": lan_ip,
        "lan_cidr": "%s/%d" % (lan_ip, prefix) if lan_ip else "",
        "netmask": netmask,
        "network": network,
        "prefix": prefix,
        "public_ip": get_public_ip(),
        "gateway_mac": gateway_mac(gateway),
        "dns_listen": "%s:53" % lan_ip if lan_ip else "",
        "redir_port": REDIR_PORT,
        "tproxy_port": TPROXY_PORT,
        "mixed_port": MIXED_PORT,
        "panel_port": CONF["port"],
        "suggested_client": {
            "ip": _suggest_client(network, prefix, gateway, lan_ip),
            "netmask": netmask,
            "gateway": lan_ip,
            "dns": lan_ip,
        },
        "interfaces": ifaces,
        "dhcp_server": detect_dhcp_server(),
        "captured_at": int(time.time()),
    }


# ============================================================
# 真实局域网客户端探测（/api/clients）
# ============================================================
CLIENT_CACHE = {}
CLIENT_LOCK = threading.Lock()


def _merge_clients(records):
    now = int(time.time())
    with CLIENT_LOCK:
        for r in records:
            ip = r.get("ip")
            if not ip:
                continue
            old = CLIENT_CACHE.get(ip)
            if old:
                r["first_seen"] = old.get("first_seen", r.get("first_seen", now))
                if not r.get("hostname") and old.get("hostname"):
                    r["hostname"] = old["hostname"]
            r.setdefault("first_seen", now)
            r.setdefault("last_seen", now)
            CLIENT_CACHE[ip] = r
        for ip in list(CLIENT_CACHE):
            if now - int(CLIENT_CACHE[ip].get("last_seen", now)) > 86400:
                CLIENT_CACHE.pop(ip, None)


def _status_of(age):
    if age <= 60:
        return "online"
    if age <= 600:
        return "idle"
    return "offline"


def collect_clients_real():
    """从本机 ARP / 邻居表与活跃连接表采集真实局域网设备。"""
    now = int(time.time())
    recs = {}
    out_ip = _outbound_lan_ip()
    primary_prefix = out_ip.rsplit(".", 1)[0] + "." if out_ip and "." in out_ip else ""

    if os.name != "nt":
        _, out = run("ip neigh show", timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if not parts or not is_lan_ip(parts[0]):
                continue
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1].lower() if "lladdr" in parts else ""
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            state = parts[-1] if parts else ""
            active = state in ("REACHABLE", "DELAY", "PROBE", "STALE", "PERMANENT")
            recs[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": "网关路由" if ip.endswith(".1") else ("局域网设备-%s" % ip.split(".")[-1]),
                "vendor": vendor_of(mac),
                "first_seen": now,
                "last_seen": now if active else now - 300,
                "conn_count": 1 if active else 0,
                "status": "online" if active else "idle",
                "via_gateway": not ip.endswith(".1"),
            }

    # Windows 或补充 ARP 表解析
    if not recs:
        _, out = run("arp -a", timeout=5)
        for line in out.splitlines():
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
            if mac == "ff:ff:ff:ff:ff:ff" or not is_lan_ip(ip):
                continue
            if primary_prefix and not ip.startswith(primary_prefix):
                continue
            is_router = ip.endswith(".1") or ip.endswith(".254")
            recs[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": "主路由器 / 网关 (%s)" % ip if is_router else ("局域网终端 (%s)" % ip),
                "vendor": vendor_of(mac),
                "first_seen": now,
                "last_seen": now,
                "conn_count": 1,
                "status": "online",
                "via_gateway": not is_router,
            }

    # 统计真实连接数（Linux nf_conntrack 或 mihomo /connections 或 netstat）
    mconns = mihomo_api_safe("/connections", timeout=3)
    if isinstance(mconns, dict):
        for c in (mconns.get("connections") or []):
            meta = c.get("metadata") or {}
            sip = meta.get("sourceIP") or ""
            if is_lan_ip(sip):
                item = recs.setdefault(sip, {
                    "ip": sip, "mac": "", "hostname": meta.get("host") or ("终端-%s" % sip.split(".")[-1]),
                    "vendor": "局域网终端", "first_seen": now, "last_seen": now,
                    "conn_count": 0, "status": "online", "via_gateway": True,
                })
                item["conn_count"] += 1
                item["last_seen"] = now
                item["via_gateway"] = True
    elif os.name != "nt":
        try:
            with open("/proc/net/nf_conntrack", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = re.search(r"src=([\d.]+)", line)
                    if m and is_lan_ip(m.group(1)):
                        ip = m.group(1)
                        if ip in recs:
                            recs[ip]["conn_count"] += 1
                            recs[ip]["last_seen"] = now
        except OSError:
            pass
    else:
        _, nout = run("netstat -an", timeout=5)
        for line in nout.splitlines():
            for ip in list(recs.keys()):
                if ip in line:
                    recs[ip]["conn_count"] += 1

    return list(recs.values())


def api_clients():
    """§2 返回真实局域网终端列表。"""
    clients = collect_clients_real()
    _merge_clients(clients)
    with CLIENT_LOCK:
        all_clients = list(CLIENT_CACHE.values())
    now = int(time.time())
    for c in all_clients:
        c["status"] = _status_of(now - int(c.get("last_seen", 0)))
    all_clients.sort(key=lambda c: (-c.get("conn_count", 0), c.get("ip", "")))
    online = sum(1 for c in all_clients if c.get("status") == "online")
    return {"clients": all_clients, "total": len(all_clients), "online": online}


# ============================================================
# 实时流量采样线程（真实读取 mihomo /connections 或网卡字节计数）
# ============================================================
SPEED_LOCK = threading.Lock()
SPEED_HISTORY = collections.deque(maxlen=60)
_SAMPLE = {"down_total": 0, "up_total": 0, "last_down": 0, "last_up": 0, "last_t": 0.0, "conns": 0}


def _host_net_bytes():
    """当 mihomo 未运行时，读取本机网卡真实收发字节数（Linux /proc/net/dev 或 Windows netstat -e）。"""
    if os.name != "nt":
        try:
            rx, tx = 0, 0
            with open("/proc/net/dev", "r", encoding="utf-8") as f:
                for line in f.readlines()[2:]:
                    if ":" not in line:
                        continue
                    iface, rest = line.split(":", 1)
                    if iface.strip() == "lo":
                        continue
                    cols = rest.split()
                    if len(cols) >= 9:
                        rx += int(cols[0])
                        tx += int(cols[8])
            return rx, tx
        except Exception:  # noqa
            return None, None
    else:
        _, out = run("netstat -e", timeout=4)
        for line in out.splitlines():
            nums = re.findall(r"\b(\d{4,})\b", line)
            if len(nums) >= 2 and ("字节" in line or "Bytes" in line):
                return int(nums[0]), int(nums[1])
    return None, None


def _sample_once():
    """每 5 秒采集一次真实流量速率。"""
    now = time.time()
    data = mihomo_api_safe("/connections", timeout=3)
    if isinstance(data, dict):
        conns = data.get("connections") or []
        dt = data.get("downloadTotal")
        ut = data.get("uploadTotal")
        if dt is None:
            dt = sum(c.get("download", 0) or 0 for c in conns)
        if ut is None:
            ut = sum(c.get("upload", 0) or 0 for c in conns)
        conn_cnt = len(conns)
    else:
        dt, ut = _host_net_bytes()
        conn_cnt = 0
        if dt is None or ut is None:
            with SPEED_LOCK:
                SPEED_HISTORY.append({"t": int(now), "down": 0, "up": 0})
            return

    with SPEED_LOCK:
        if _SAMPLE["last_t"] > 0:
            el = now - _SAMPLE["last_t"]
            if el > 0 and dt >= _SAMPLE["last_down"] and ut >= _SAMPLE["last_up"]:
                ds = int((dt - _SAMPLE["last_down"]) / el)
                us = int((ut - _SAMPLE["last_up"]) / el)
                SPEED_HISTORY.append({"t": int(now), "down": max(0, ds), "up": max(0, us)})
        else:
            SPEED_HISTORY.append({"t": int(now), "down": 0, "up": 0})
        _SAMPLE["last_t"] = now
        _SAMPLE["last_down"] = dt
        _SAMPLE["last_up"] = ut
        _SAMPLE["down_total"] = dt
        _SAMPLE["up_total"] = ut
        _SAMPLE["conns"] = conn_cnt


def _speed_loop():
    while True:
        try:
            _sample_once()
        except Exception:  # noqa
            pass
        time.sleep(5)


def start_speed_sampler():
    _sample_once()
    t = threading.Thread(target=_speed_loop, name="speed-sampler", daemon=True)
    t.start()
    return t


def speed_history_snapshot():
    with SPEED_LOCK:
        return list(SPEED_HISTORY)


# ============================================================
# 真实订阅拉取、解析（支持 Clash YAML 与 Base64 节点链接）与 TCP 测速
# ============================================================
def _b64_decode_safe(s):
    """宽松 Base64 解码（支持 URL-safe 及缺省 = 填充）。"""
    s = re.sub(r"\s+", "", s or "")
    if not s:
        return ""
    pad = (-len(s)) % 4
    s += "=" * pad
    try:
        return base64.urlsafe_b64decode(s.encode("ascii")).decode("utf-8", errors="replace")
    except Exception:  # noqa
        return ""


def _parse_uri_line(line):
    """解析单条分享链接（vmess/ss/trojan/vless/hysteria2/hy2/tuic）为节点字典。"""
    line = (line or "").strip()
    if not line or "://" not in line:
        return None
    scheme, rest = line.split("://", 1)
    scheme = scheme.lower()
    if scheme == "vmess":
        raw = _b64_decode_safe(rest)
        try:
            obj = json.loads(raw)
            name = str(obj.get("ps") or obj.get("add") or "VMess节点").strip()
            server = str(obj.get("add") or "").strip()
            port = int(obj.get("port") or 443)
            if server:
                return {"name": name, "type": "vmess", "server": server, "port": port, "udp": True}
        except Exception:  # noqa
            return None
    elif scheme in ("ss", "trojan", "vless", "hysteria2", "hy2", "tuic", "ssr"):
        try:
            name = ""
            if "#" in rest:
                rest, frag = rest.split("#", 1)
                name = urllib.parse.unquote(frag).strip()
            if "@" in rest:
                _, hostpart = rest.rsplit("@", 1)
            else:
                dec = _b64_decode_safe(rest.split("?")[0])
                hostpart = dec.rsplit("@", 1)[-1] if "@" in dec else ""
            hostpart = hostpart.split("?")[0].split("/")[0].strip()
            if ":" in hostpart:
                server, pstr = hostpart.rsplit(":", 1)
                server = server.strip("[]")
                port = int(re.match(r"^\d+", pstr).group(0))
                ntype = "hysteria2" if scheme == "hy2" else scheme
                return {
                    "name": name or ("%s:%d" % (server, port)),
                    "type": ntype,
                    "server": server,
                    "port": port,
                    "udp": True,
                }
        except Exception:  # noqa
            return None
    return None


def _parse_subscription_content(text, sub_id, sub_name):
    """解析订阅返回文本（支持 Clash YAML proxies 块 或 Base64 URI 列表），返回 (nodes_list, yaml_lines)。"""
    text = (text or "").strip()
    if not text:
        return [], []

    nodes = []
    yaml_lines = []

    # 情况 1：Clash YAML 格式（含 proxies:）
    if re.search(r"(?m)^proxies\s*:", text):
        lines = text.splitlines()
        in_proxies = False
        cur_block = {}
        for line in lines:
            if re.match(r"^proxies\s*:", line):
                in_proxies = True
                continue
            if not in_proxies:
                continue
            if re.match(r"^[A-Za-z0-9_-]+\s*:", line):
                break
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue
            yaml_lines.append(line)
            # 解析行内或块级 name / type / server / port
            if sline.startswith("-"):
                if cur_block.get("name"):
                    nodes.append(cur_block)
                cur_block = {"sub_id": sub_id, "sub_name": sub_name, "udp": "udp: true" in sline.lower()}
            for key in ("name", "type", "server", "port"):
                m = re.search(r"(?:^|[,{\s])%s\s*:\s*(['\"]?)([^,'\"}\n]+)\1" % key, sline)
                if m:
                    val = m.group(2).strip()
                    cur_block[key] = int(val) if (key == "port" and val.isdigit()) else val
        if cur_block.get("name"):
            nodes.append(cur_block)
        return nodes, yaml_lines

    # 情况 2：Base64 编码或纯文本 URI 列表
    decoded = _b64_decode_safe(text) if "://" not in text[:60] else text
    for ln in (decoded or text).splitlines():
        nd = _parse_uri_line(ln)
        if nd:
            nd["sub_id"] = sub_id
            nd["sub_name"] = sub_name
            nodes.append(nd)
            safe_nm = nd["name"].replace('"', "'")
            yaml_lines.append('  - {name: "%s", type: %s, server: %s, port: %d, udp: true}' % (
                safe_nm, nd["type"], nd["server"], int(nd.get("port") or 443)
            ))
    return nodes, yaml_lines


def _tcp_ping_node(node, timeout=2.2):
    """对节点服务器执行真实 TCP 握手测速，返回毫秒延迟（失败返回 0）。"""
    server = (node.get("server") or "").strip()
    port = int(node.get("port") or 0)
    if not server or port <= 0:
        return 0
    t0 = time.perf_counter()
    try:
        with socket.create_connection((server, port), timeout=timeout):
            ms = int(round((time.perf_counter() - t0) * 1000))
            return max(1, ms)
    except Exception:  # noqa
        return 0


def run_tcp_healthcheck(nodes, max_workers=16):
    """并发对解析出的真实节点进行 TCP 握手测速，更新 delay 与 history。"""
    if not nodes:
        return
    with ThreadPoolExecutor(max_workers=min(max_workers, len(nodes))) as ex:
        delays = list(ex.map(_tcp_ping_node, nodes))
    for nd, d in zip(nodes, delays):
        nd["delay"] = d
        nd["alive"] = d > 0
        hist = list(nd.get("history") or [])
        hist.append(d)
        nd["history"] = hist[-10:]


def _fetch_url_text(url, timeout=25):
    """真实下载订阅链接内容。"""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "clash.meta/v1.19.32"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


# ============================================================
# 多订阅管理与节点池构建
# ============================================================
def _infer_sub_name(url, idx):
    try:
        u = urllib.parse.urlparse(url)
        host = (u.hostname or "").lower()
        if host:
            parts = host.split(".")
            core = parts[-2] if len(parts) >= 2 else parts[0]
            return "订阅源 %d (%s)" % (idx, core)
    except Exception:  # noqa
        pass
    return "订阅源 #%d" % idx


def _load_subs():
    """加载多订阅配置列表；首次若 subscribe_url.txt 非空则自动迁移。"""
    with _STATE_LOCK:
        _load_state()
        subs = _STATE.get("subscriptions")
        if not subs and os.path.isfile(SUB_URL_FILE):
            try:
                with open(SUB_URL_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "|" in line and line.split("|", 1)[1].strip().startswith("http"):
                            nm, u = line.split("|", 1)
                            nm, u = nm.strip(), u.strip()
                        else:
                            u = line
                            nm = _infer_sub_name(u, len(subs) + 1)
                        subs.append({
                            "id": "sub_%d" % (len(subs) + 1),
                            "name": nm or ("订阅源 #%d" % (len(subs) + 1)),
                            "raw_url": u,
                            "enabled": True,
                            "nodes": 0,
                            "updated_at": int(time.time()),
                            "status": "ok",
                            "error": "",
                        })
                if subs:
                    _save_state()
            except OSError:
                pass
        return subs


def _sync_subs_files(subs, all_yaml_lines=None):
    """同步写入 subscribe_url.txt 及合并后的 providers/sub.yaml。"""
    try:
        os.makedirs(MIHOMO_DIR, exist_ok=True)
        with open(SUB_URL_FILE, "w", encoding="utf-8") as f:
            for s in subs:
                if s.get("enabled", True) and s.get("raw_url"):
                    safe_name = (s.get("name") or "订阅").replace("|", "-").strip()
                    f.write("%s|%s\n" % (safe_name, s["raw_url"].strip()))
        if all_yaml_lines is not None:
            os.makedirs(os.path.dirname(SUB_FILE), exist_ok=True)
            with open(SUB_FILE, "w", encoding="utf-8") as f:
                if all_yaml_lines:
                    f.write("proxies:\n" + "\n".join(all_yaml_lines) + "\n")
                else:
                    f.write("proxies: []\n")
        return True
    except OSError:
        return False


def _pull_subscriptions(target_sub_id=None):
    """拉取一个或所有启用中的真实订阅、解析合并节点并执行 TCP 测速。"""
    subs = _load_subs()
    enabled = [s for s in subs if s.get("enabled", True)]
    if not enabled:
        with _STATE_LOCK:
            _STATE["parsed_nodes"] = []
            _save_state()
        _sync_subs_files(subs, [])
        return False, "当前没有启用中的订阅源"

    now = int(time.time())
    with _STATE_LOCK:
        old_nodes_by_sub = collections.defaultdict(list)
        for nd in (_STATE.get("parsed_nodes") or []):
            old_nodes_by_sub[nd.get("sub_id", "")].append(nd)

    merged_nodes = []
    merged_yaml = []
    seen_names = set()
    ok_subs = 0
    errors = []

    for s in enabled:
        sid = s["id"]
        sname = s.get("name") or sid
        url = (s.get("raw_url") or "").strip()
        should_pull = (target_sub_id is None) or (sid == target_sub_id) or (not old_nodes_by_sub.get(sid))

        if should_pull:
            try:
                content = _fetch_url_text(url, timeout=25)
                pnodes, ylines = _parse_subscription_content(content, sid, sname)
                if not pnodes:
                    s["status"] = "error"
                    s["error"] = "返回内容未解析到有效节点（非 Clash YAML 或 Base64 订阅）"
                    errors.append("%s: 未解析到节点" % sname)
                    continue
                # 给多订阅节点去重命名并构建对象
                built = []
                for raw in pnodes:
                    nm = str(raw.get("name") or "节点").strip()
                    if len(enabled) > 1 and not nm.startswith("["):
                        nm = "[%s] %s" % (sname, nm)
                    base_nm = nm
                    k = 2
                    while nm in seen_names:
                        nm = "%s #%d" % (base_nm, k)
                        k += 1
                    seen_names.add(nm)
                    reg, reg_name = detect_region(nm)
                    built.append({
                        "name": nm,
                        "type": raw.get("type") or "ss",
                        "server": raw.get("server") or "",
                        "port": int(raw.get("port") or 443),
                        "udp": bool(raw.get("udp", True)),
                        "delay": 0,
                        "alive": False,
                        "history": [],
                        "region": reg,
                        "region_name": reg_name,
                        "sub_id": sid,
                        "sub_name": sname,
                    })
                run_tcp_healthcheck(built)
                s["nodes"] = len(built)
                s["updated_at"] = now
                s["status"] = "ok"
                s["error"] = ""
                merged_nodes.extend(built)
                merged_yaml.extend(ylines)
                ok_subs += 1
            except Exception as e:  # noqa
                s["status"] = "error"
                s["error"] = "拉取失败: %s" % e
                errors.append("%s: %s" % (sname, e))
                # 保留旧节点兜底
                if old_nodes_by_sub.get(sid):
                    merged_nodes.extend(old_nodes_by_sub[sid])
        else:
            prev = old_nodes_by_sub.get(sid, [])
            merged_nodes.extend(prev)
            ok_subs += 1

    with _STATE_LOCK:
        _STATE["parsed_nodes"] = merged_nodes
        if merged_nodes and not _STATE.get("selected_node"):
            alive_first = next((n["name"] for n in merged_nodes if n.get("alive")), merged_nodes[0]["name"])
            _STATE["selected_node"] = alive_first
        _save_state()

    _sync_subs_files(subs, merged_yaml if merged_yaml else None)

    # 若 mihomo 正在运行（无论 Linux 或 Windows），触发热重载 provider 与配置
    if service_active("mihomo"):
        mihomo_api_safe("/providers/proxies/sub", method="PUT", timeout=10)
        mihomo_api_safe("/configs?force=true", method="PUT", payload={"path": CONFIG_FILE}, timeout=10)

    if ok_subs == 0:
        return False, "订阅拉取失败：" + "；".join(errors)
    msg = "成功更新 %d 个订阅，共解析 %d 个真实节点" % (ok_subs, len(merged_nodes))
    if errors:
        msg += "（部分失败：%s）" % "；".join(errors)
    return True, msg


# ============================================================
# 业务 API —— 节点管理（§3）
# ============================================================
def _stats_of(nodes):
    total = len(nodes)
    alive_nodes = [n for n in nodes if n.get("alive") and (n.get("delay") or 0) > 0]
    alive = len(alive_nodes)
    timeout = total - alive
    best = min(alive_nodes, key=lambda n: n["delay"])["name"] if alive_nodes else ""
    avg = int(sum(n["delay"] for n in alive_nodes) / alive) if alive else 0
    return {"total": total, "alive": alive, "timeout": timeout, "best": best, "avg_delay": avg}


def api_proxies():
    """§3 返回真实节点列表（优先合并 mihomo 实时状态与已解析的多订阅节点池）。"""
    favorites = get_favorites()
    subs = _load_subs()
    enabled_ids = {s["id"] for s in subs if s.get("enabled", True)}

    with _STATE_LOCK:
        _load_state()
        parsed = [dict(n) for n in (_STATE.get("parsed_nodes") or []) if n.get("sub_id") in enabled_ids]
        selected = _STATE.get("selected_node") or ""
        last_used = dict(_STATE.get("last_used") or {})

    # 尝试从运行中的 mihomo API 获取实时节点与延迟
    allp = mihomo_api_safe("/proxies", timeout=4)
    prov = mihomo_api_safe("/providers/proxies", timeout=4)

    if isinstance(allp, dict) or isinstance(prov, dict):
        proxies = (allp or {}).get("proxies") or {}
        grp = proxies.get(GROUP_NAME) or {}
        if grp.get("now"):
            selected = grp["now"]
        parsed_map = {n["name"]: n for n in parsed}
        live_nodes = []
        raw_list = []
        if isinstance(prov, dict):
            for pdata in (prov.get("proxies") or {}).values():
                raw_list.extend(pdata.get("proxies") or [])
        for r in raw_list:
            nm = r.get("name", "")
            if not nm or nm in ("DIRECT", "REJECT", "GLOBAL"):
                continue
            hist = [int(h.get("delay") or 0) for h in (r.get("history") or [])][-10:]
            delay = hist[-1] if hist else 0
            pmeta = parsed_map.get(nm, {})
            reg, reg_name = detect_region(nm)
            live_nodes.append({
                "name": nm,
                "type": r.get("type") or pmeta.get("type") or "",
                "udp": bool(r.get("udp", True)),
                "delay": delay,
                "alive": bool(delay > 0 or r.get("alive")),
                "history": hist,
                "region": reg,
                "region_name": reg_name,
                "sub_id": pmeta.get("sub_id", ""),
                "sub_name": pmeta.get("sub_name", ""),
                "now": nm == selected,
                "last_used": int(last_used.get(nm, 0)),
            })
        if live_nodes:
            parsed = live_nodes

    if parsed and (not selected or all(n["name"] != selected for n in parsed)):
        selected = next((n["name"] for n in parsed if n.get("alive")), parsed[0]["name"])

    by_sub = collections.defaultdict(list)
    for n in parsed:
        n["now"] = (n["name"] == selected)
        n["last_used"] = int(last_used.get(n["name"], 0))
        by_sub[n.get("sub_id", "")].append(n)

    groups = []
    if parsed:
        groups.append({"name": "sub", "label": "全部订阅节点", "nodes": parsed})
        for s in subs:
            if s.get("enabled", True) and by_sub.get(s["id"]):
                groups.append({
                    "name": "sub:" + s["id"],
                    "label": s["name"],
                    "sub_id": s["id"],
                    "nodes": by_sub[s["id"]],
                })

    return {
        "current": selected,
        "groups": groups,
        "stats": _stats_of(parsed),
        "favorites": favorites,
        "selected_in_group": {GROUP_NAME: selected} if selected else {},
        "subscriptions": [
            {"id": s["id"], "name": s["name"], "enabled": bool(s.get("enabled", True)), "nodes": len(by_sub.get(s["id"], []))}
            for s in subs
        ],
        "captured_at": int(time.time()),
    }


def _find_node(name):
    data = api_proxies()
    for g in data.get("groups", []):
        for n in g.get("nodes", []):
            if n.get("name") == name:
                return n
    return None


def api_select(name):
    """切换当前使用节点。"""
    if not name:
        return {"ok": False, "msg": "缺少节点名"}
    with _STATE_LOCK:
        _load_state()
        _STATE["selected_node"] = name
        _STATE.setdefault("last_used", {})[name] = int(time.time())
        _save_state()
    if service_active("mihomo"):
        try:
            mihomo_api("/proxies/%s" % GROUP_NAME, method="PUT", payload={"name": name})
        except Exception as e:  # noqa
            return {"ok": False, "msg": "mihomo 切换失败: %s" % e}
    return {"ok": True, "msg": "已切换到 %s" % name}


def api_healthcheck():
    """触发全节点真实测速（mihomo healthcheck + 本机并发 TCP 握手实测）。"""
    if service_active("mihomo"):
        mihomo_api_safe("/providers/proxies/sub/healthcheck", timeout=30)
    with _STATE_LOCK:
        _load_state()
        nodes = _STATE.get("parsed_nodes") or []
    if nodes:
        run_tcp_healthcheck(nodes)
        with _STATE_LOCK:
            _save_state()
        alive = sum(1 for n in nodes if n.get("alive"))
        return {"ok": True, "msg": "已完成 %d 个节点真实测速（%d 个可用）" % (len(nodes), alive)}
    return {"ok": True, "msg": "已触发测速（请先导入订阅以获取节点）"}


def api_autoselect(strategy):
    """按策略自动选择最优真实节点。"""
    if strategy not in ("fastest", "stable", "random"):
        return {"ok": False, "msg": "不支持的策略，可选 fastest|stable|random"}
    data = api_proxies()
    nodes = data["groups"][0]["nodes"] if data.get("groups") else []
    alive = [n for n in nodes if n.get("alive") and (n.get("delay") or 0) > 0]
    if not alive:
        return {"ok": False, "msg": "当前没有可用的在线节点，请先导入订阅并测速"}

    if strategy == "fastest":
        pick = min(alive, key=lambda n: n["delay"])
    elif strategy == "random":
        pick = random.choice(alive)
    else:
        def variance(n):
            h = [x for x in (n.get("history") or []) if x > 0]
            if len(h) < 2:
                return (0.0, n["delay"])
            avg = sum(h) / len(h)
            return (sum((x - avg) ** 2 for x in h) / len(h), avg)
        pick = min(alive, key=variance)

    api_select(pick["name"])
    return {
        "ok": True,
        "msg": "已自动切换到 %s（实测延迟 %dms）" % (pick["name"], pick["delay"]),
        "data": {"name": pick["name"], "delay": pick["delay"]},
    }


def api_favorite(name):
    if not name:
        return {"ok": False, "msg": "缺少节点名"}
    favs = toggle_favorite(name)
    added = name in favs
    return {
        "ok": True,
        "msg": "已收藏 %s" % name if added else "已取消收藏 %s" % name,
        "favorites": favs,
        "data": {"favorites": favs},
    }


def api_nodehistory(name):
    if not name:
        return {"ok": False, "msg": "缺少节点名"}
    node = _find_node(name)
    if not node:
        return {"ok": False, "msg": "节点不存在"}
    return {
        "ok": True,
        "data": {
            "name": name,
            "history": node.get("history", []),
            "delay": node.get("delay", 0),
            "region": node.get("region", "OTHER"),
        },
    }


# ============================================================
# 业务 API —— 系统真实体检（§4）
# ============================================================
def _check(key, name, status, detail):
    return {"key": key, "name": name, "status": status, "detail": detail}


def api_health():
    """§4 真实检测 9 项系统与网关指标。"""
    checks = []
    # 1. mihomo
    if service_active("mihomo"):
        ver = mihomo_api_safe("/version") or {}
        vtxt = ver.get("version") or ver.get("meta") or "运行中"
        checks.append(_check("mihomo", "mihomo 核心服务", "pass", "运行中 (%s)" % vtxt))
    else:
        checks.append(_check("mihomo", "mihomo 核心服务", "warn", "未检测到 mihomo 运行（127.0.0.1:9090 未响应）"))

    # 2. tproxy
    if os.name != "nt" and os.path.isfile(TPROXY_SH):
        _, out = run("bash %s status" % TPROXY_SH, timeout=8)
        if ("MIHOMO_REDIR" in out and "未启用" not in out) or ("TPROXY_STATE=on" in out):
            checks.append(_check("tproxy", "透明代理规则", "pass", "iptables nat/mangle 规则已生效"))
        else:
            checks.append(_check("tproxy", "透明代理规则", "warn", "透明代理规则未开启"))
    else:
        checks.append(_check("tproxy", "透明代理规则", "warn", "当前非 Linux 网关环境或尚未启用 TProxy"))

    # 3. dns
    lan = api_network()
    _, out_ss = run("ss -lun" if os.name != "nt" else "netstat -ano", timeout=5)
    if re.search(r":53\s", out_ss):
        checks.append(_check("dns", "DNS 53 端口监听", "pass", "正在监听 (%s)" % (lan.get("dns_listen") or ":53")))
    else:
        checks.append(_check("dns", "DNS 53 端口监听", "warn", "未检测到 53 端口 DNS 监听"))

    # 4. ipfwd
    if os.name != "nt":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as f:
                fwd = f.read().strip()
        except OSError:
            fwd = "0"
        if fwd == "1":
            checks.append(_check("ipfwd", "内核 IP 转发", "pass", "net.ipv4.ip_forward = 1"))
        else:
            checks.append(_check("ipfwd", "内核 IP 转发", "warn", "net.ipv4.ip_forward 未开启"))
    else:
        checks.append(_check("ipfwd", "本机局域网连通", "pass" if lan.get("lan_ip") else "warn",
                             "本机局域网 IP: %s" % (lan.get("lan_ip") or "未获取到")))

    # 5. sub
    sub_info = api_subscription_get()
    if sub_info.get("configured"):
        stats = api_proxies().get("stats", {})
        total = stats.get("total", 0)
        alive = stats.get("alive", 0)
        if total > 0 and alive > 0:
            checks.append(_check("sub", "多订阅节点池", "pass",
                                 "已启用 %d 个订阅，%d/%d 个节点可用" % (sub_info.get("enabled_subs", 1), alive, total)))
        elif total > 0:
            checks.append(_check("sub", "多订阅节点池", "warn", "已导入 %d 个节点，但测速全部超时" % total))
        else:
            checks.append(_check("sub", "多订阅节点池", "warn", "订阅已配置，尚未拉取到节点"))
    else:
        checks.append(_check("sub", "多订阅节点池", "warn", "尚未导入订阅链接（请前往「订阅」页导入）"))

    # 6. node
    prox = api_proxies()
    cur = prox.get("current", "")
    if cur:
        nd = _find_node(cur) or {}
        d = nd.get("delay", 0)
        checks.append(_check("node", "当前选中节点", "pass" if d > 0 else "warn",
                             "%s（%s）" % (cur, ("%dms" % d) if d > 0 else "未测速/超时")))
    else:
        checks.append(_check("node", "当前选中节点", "warn", "尚未选择节点"))

    # 7. public
    pip = lan.get("public_ip") or get_public_ip()
    if pip:
        checks.append(_check("public", "公网出口连通", "pass", "真实公网出口 IP: %s" % pip))
    else:
        checks.append(_check("public", "公网出口连通", "warn", "公网出口 IP 探测超时"))

    # 8. disk
    try:
        du = shutil.disk_usage(PROJECT_DIR)
        free_gb = du.free / 1073741824.0
        checks.append(_check("disk", "磁盘可用空间", "pass" if free_gb >= 1.0 else "warn", "剩余 %.1f GB" % free_gb))
    except Exception:  # noqa
        checks.append(_check("disk", "磁盘可用空间", "warn", "无法读取磁盘空间"))

    # 9. load
    try:
        la = os.getloadavg()[0]
        checks.append(_check("load", "系统负载", "pass", "1分钟负载 %.2f" % la))
    except (OSError, AttributeError):
        checks.append(_check("load", "系统运行状态", "pass", "面板已连续运行 %d 秒" % int(time.time() - SERVER_START_TIME)))

    fails = sum(1 for c in checks if c["status"] == "fail")
    warns = sum(1 for c in checks if c["status"] == "warn")
    score = max(0, min(100, 100 - fails * 20 - warns * 7))
    level = "poor" if fails >= 2 else ("fair" if (fails >= 1 or warns >= 3) else "good")
    return {"score": score, "level": level, "checks": checks, "captured_at": int(time.time())}


# ============================================================
# 业务 API —— 概览（§5）与终端连接判定（§2）
# ============================================================
def _mem_mb():
    if os.name != "nt":
        _, out = run("ps -o rss= -C mihomo", timeout=4)
        for line in out.splitlines():
            if line.strip().isdigit():
                return round(int(line.strip()) / 1024.0, 1)
    return 0.0


def _uptime_sec():
    if os.name != "nt":
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                return int(float(f.read().split()[0]))
        except Exception:  # noqa
            pass
    return int(time.time() - SERVER_START_TIME)


def api_overview():
    """§5 真实概览数据。"""
    hist = speed_history_snapshot()
    last = hist[-1] if hist else {"down": 0, "up": 0}
    net = api_network()
    prox = api_proxies()
    st = prox.get("stats", {})
    sub_info = api_subscription_get()
    clients = api_clients()

    tproxy_on = _is_tproxy_or_sysproxy_on()

    ver_info = mihomo_api_safe("/version")
    version = (ver_info.get("version") or ver_info.get("meta") or "") if isinstance(ver_info, dict) else ""

    with SPEED_LOCK:
        conns = _SAMPLE["conns"]
        down_total = _SAMPLE["down_total"]
        up_total = _SAMPLE["up_total"]

    if not conns:
        conns = sum(c.get("conn_count", 0) for c in clients.get("clients", []))

    return {
        "mihomo": service_active("mihomo"),
        "tproxy": tproxy_on,
        "version": version,
        "current": prox.get("current", ""),
        "nodes_total": st.get("total", 0),
        "nodes_alive": st.get("alive", 0),
        "sub_configured": bool(sub_info.get("configured")),
        "error": "",
        "uptime_sec": _uptime_sec(),
        "conns": conns,
        "mem_mb": _mem_mb(),
        "down_total": down_total,
        "up_total": up_total,
        "down_speed": last.get("down", 0),
        "up_speed": last.get("up", 0),
        "speed_history": hist,
        "clients_online": clients.get("online", 0),
        "lan_ip": net.get("lan_ip", ""),
        "public_ip": net.get("public_ip", ""),
        "captured_at": int(time.time()),
    }


def _ct_check(key, name, passed, detail):
    return {"key": key, "name": name, "pass": bool(passed), "detail": detail}


def api_connecttest(client_ip):
    """§2 真实检测来访终端设备与本网关的连接状态。"""
    net = api_network()
    gw = net.get("lan_ip", "")
    network = net.get("network", "")
    prefix = net.get("prefix", 24)
    cidr_lo = _ip2int(network) if network else None
    cidr_hi = _ip2int(broadcast_addr(network, prefix)) if network else None

    def in_subnet(ip):
        v = _ip2int(ip or "")
        if v is None or cidr_lo is None or cidr_hi is None:
            return False
        return cidr_lo <= v <= cidr_hi

    cip = client_ip or ""
    if cip in ("127.0.0.1", "::1") and gw:
        cip = gw
    cmac = gateway_mac(cip) if cip else ""

    reach = True
    same_lan = bool(cip and (cip == gw or in_subnet(cip)))

    # 检查 DNS 53 是否就绪
    _, out_ss = run("ss -lun" if os.name != "nt" else "netstat -ano", timeout=4)
    dns_listening = bool(re.search(r":53\s", out_ss))
    proxy_running = service_active("mihomo")

    checks = [
        _ct_check("reach", "连通网关面板", reach, "终端 (%s) 到网关 (%s) HTTP 通信正常" % (cip or "本机", gw or "本机")),
        _ct_check("gw", "同网段可达", same_lan,
                  "终端与网关处于同一局域网段 (%s)" % (net.get("lan_cidr") or gw) if same_lan else "当前访问 IP 不在网关同网段"),
        _ct_check("dns", "DNS 接管服务", dns_listening,
                  "网关 53 端口 DNS 正在监听" if dns_listening else "网关尚未开启 53 端口 DNS 监听（请启动 mihomo）"),
        _ct_check("proxy", "透明代理核心", proxy_running,
                  "mihomo 代理核心正在运行" if proxy_running else "mihomo 核心尚未启动"),
    ]
    hints = []
    if not same_lan and gw:
        hints.append("请确保终端与网关连接在同一局域网，并将终端网关设为 %s" % gw)
    if not dns_listening and gw:
        hints.append("网关本机尚未监听 53 端口，请在网关启动 mihomo 服务，并将终端 DNS 设为 %s" % gw)
    if not proxy_running:
        hints.append("mihomo 服务尚未运行，启动后即可生效透明代理分流")

    if reach and same_lan and dns_listening and proxy_running:
        verdict, verdict_text = "connected", "已接入网关，分流代理生效"
    elif reach and same_lan:
        verdict, verdict_text = "partial", "已连通网关本机（%s），等待启动 mihomo 核心开启透明分流" % (gw or "127.0.0.1")
    else:
        verdict, verdict_text = "not_connected", "尚未接入网关，请按向导配置静态 IP 与网关"

    return {
        "client_ip": cip,
        "client_mac": cmac,
        "gateway_ip": gw,
        "via_gateway": same_lan,
        "dns_ok": dns_listening,
        "proxy_ok": proxy_running,
        "verdict": verdict,
        "verdict_text": verdict_text,
        "checks": checks,
        "hints": hints,
    }


# ============================================================
# 业务 API —— 多订阅增删改查与服务控制（§7）
# ============================================================
def _format_sub_public(s, node_counts):
    sid = s.get("id", "")
    cnt = node_counts.get(sid, s.get("nodes", 0))
    return {
        "id": sid,
        "name": s.get("name") or sid,
        "url": mask_url(s.get("raw_url") or s.get("url") or ""),
        "enabled": bool(s.get("enabled", True)),
        "nodes": int(cnt or 0),
        "updated_at": int(s.get("updated_at") or 0),
        "status": s.get("status") or ("ok" if s.get("enabled", True) else "disabled"),
        "error": s.get("error") or "",
    }


def api_subscription_get():
    """返回真实多订阅列表与汇总状态。"""
    subs = _load_subs()
    with _STATE_LOCK:
        _load_state()
        counts = collections.Counter(n.get("sub_id", "") for n in (_STATE.get("parsed_nodes") or []))
    pub_subs = [_format_sub_public(s, counts) for s in subs]
    enabled_subs = [s for s in pub_subs if s["enabled"]]
    total_nodes = sum(s["nodes"] for s in enabled_subs)
    first_url = enabled_subs[0]["url"] if enabled_subs else (pub_subs[0]["url"] if pub_subs else "")
    return {
        "url": first_url,
        "configured": len(pub_subs) > 0,
        "nodes": total_nodes,
        "subscriptions": pub_subs,
        "total_subs": len(pub_subs),
        "enabled_subs": len(enabled_subs),
    }


def api_subscription_refresh(sub_id=None):
    """刷新单个或全部启用中的真实订阅。"""
    ok, msg = _pull_subscriptions(target_sub_id=sub_id)
    return {"ok": ok, "msg": msg, "data": api_subscription_get()}


def _parse_sub_inputs(body):
    if isinstance(body, str):
        body = {"url": body}
    body = body or {}
    raw_items = []
    if isinstance(body.get("items"), list):
        for it in body["items"]:
            if isinstance(it, dict) and it.get("url"):
                raw_items.append({"name": (it.get("name") or "").strip(), "url": it["url"].strip()})
    if isinstance(body.get("urls"), list):
        for u in body["urls"]:
            if isinstance(u, str) and u.strip():
                raw_items.append({"name": "", "url": u.strip()})
    raw_url = (body.get("url") or "").strip()
    default_name = (body.get("name") or "").strip()
    if raw_url:
        lines = [ln.strip() for ln in raw_url.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        for i, ln in enumerate(lines):
            if "|" in ln and ln.split("|", 1)[1].strip().startswith("http"):
                nm, u = ln.split("|", 1)
                raw_items.append({"name": nm.strip(), "url": u.strip()})
            else:
                nm = default_name if (len(lines) == 1 and i == 0) else ""
                raw_items.append({"name": nm, "url": ln})
    return [it for it in raw_items if it["url"].startswith(("http://", "https://"))]


def api_subscription_set(body_or_url):
    """添加或批量导入多个真实订阅链接并立即拉取解析节点。"""
    payload = {"url": body_or_url} if isinstance(body_or_url, str) else (body_or_url or {})
    items = _parse_sub_inputs(payload)
    if not items:
        return {"ok": False, "msg": "请填写完整的 http(s):// 订阅链接（支持多行批量导入，每行一条或 名称|链接）"}

    mode = (payload.get("mode") or "append").lower()
    now = int(time.time())
    subs = _load_subs()

    with _STATE_LOCK:
        if mode == "replace":
            subs.clear()
            _STATE["parsed_nodes"] = []
        for it in items:
            u = it["url"]
            existing = next((s for s in subs if s.get("raw_url") == u), None)
            if existing:
                if it["name"]:
                    existing["name"] = it["name"]
                existing["enabled"] = True
                existing["updated_at"] = now
            else:
                new_idx = len(subs) + 1
                sid = "sub_%d_%d" % (new_idx, int(time.time() * 1000) % 10000)
                nm = it["name"] or _infer_sub_name(u, new_idx)
                subs.append({
                    "id": sid,
                    "name": nm,
                    "raw_url": u,
                    "enabled": True,
                    "nodes": 0,
                    "updated_at": now,
                    "status": "ok",
                    "error": "",
                })
        _save_state()

    ok, msg = _pull_subscriptions()
    return {"ok": ok, "msg": msg, "data": api_subscription_get()}


def api_subscription_toggle(sub_id, enabled=None):
    """启用或停用指定订阅。"""
    if not sub_id:
        return {"ok": False, "msg": "缺少订阅 ID"}
    subs = _load_subs()
    target = None
    with _STATE_LOCK:
        for s in subs:
            if s["id"] == sub_id:
                s["enabled"] = (not s.get("enabled", True)) if enabled is None else bool(enabled)
                s["status"] = "ok" if s["enabled"] else "disabled"
                target = s
                break
        if target:
            _save_state()
    if not target:
        return {"ok": False, "msg": "未找到该订阅"}
    _sync_subs_files(subs)
    return {
        "ok": True,
        "msg": "已%s订阅「%s」" % ("启用" if target["enabled"] else "停用", target["name"]),
        "data": api_subscription_get(),
    }


def api_subscription_delete(sub_id):
    """删除指定订阅及其节点。"""
    if not sub_id:
        return {"ok": False, "msg": "缺少订阅 ID"}
    subs = _load_subs()
    removed = None
    with _STATE_LOCK:
        idx = next((i for i, s in enumerate(subs) if s["id"] == sub_id), -1)
        if idx >= 0:
            removed = subs.pop(idx)
            _STATE["parsed_nodes"] = [n for n in (_STATE.get("parsed_nodes") or []) if n.get("sub_id") != sub_id]
            _save_state()
    if not removed:
        return {"ok": False, "msg": "未找到该订阅"}
    _sync_subs_files(subs)
    return {
        "ok": True,
        "msg": "已删除订阅「%s」" % removed.get("name", sub_id),
        "data": api_subscription_get(),
    }


def api_subscription_update(sub_id, name="", url=""):
    """修改订阅名称或链接。"""
    if not sub_id:
        return {"ok": False, "msg": "缺少订阅 ID"}
    name = (name or "").strip()
    url = (url or "").strip()
    subs = _load_subs()
    target = None
    with _STATE_LOCK:
        for s in subs:
            if s["id"] == sub_id:
                if name:
                    s["name"] = name
                    for n in (_STATE.get("parsed_nodes") or []):
                        if n.get("sub_id") == sub_id:
                            n["sub_name"] = name
                if url and url.startswith("http") and "***" not in url:
                    s["raw_url"] = url
                s["updated_at"] = int(time.time())
                target = s
                break
        if target:
            _save_state()
    if not target:
        return {"ok": False, "msg": "未找到该订阅"}
    _sync_subs_files(subs)
    return {"ok": True, "msg": "已更新订阅「%s」" % target.get("name", sub_id), "data": api_subscription_get()}


# ============================================================
# 跨平台 mihomo 核心检测、多镜像一键安装与进程管控（Windows + Linux 通用）
# ============================================================
MIHOMO_RELEASE_VER = "v1.19.21"
CORE_MIRRORS = [
    {"id": "ghfast",  "name": "国内高速镜像 1 (ghfast.top · 推荐)", "prefix": "https://ghfast.top/"},
    {"id": "ghproxy", "name": "国内高速镜像 2 (gh-proxy.com)",      "prefix": "https://gh-proxy.com/"},
    {"id": "moeyy",   "name": "国内高速镜像 3 (moeyy.xyz)",         "prefix": "https://github.moeyy.xyz/"},
    {"id": "direct",  "name": "GitHub 官方源 (直连)",               "prefix": ""},
]
_MIHOMO_PROC_LOCK = threading.Lock()
_MIHOMO_PROC = None
_MIHOMO_LOG_FP = None


def _detect_os_arch():
    """识别当前操作系统 (windows/linux/darwin) 与 CPU 架构 (amd64/arm64/armv7)。"""
    sys_name = "windows" if os.name == "nt" else ("darwin" if platform.system().lower() == "darwin" else "linux")
    mach = (platform.machine() or "").lower()
    if mach in ("x86_64", "amd64", "x64"):
        arch = "amd64"
    elif mach in ("aarch64", "arm64"):
        arch = "arm64"
    elif "arm" in mach:
        arch = "armv7"
    else:
        arch = "amd64"
    return sys_name, arch


def _find_local_mihomo_candidates():
    """扫描本机已有的 mihomo / verge-mihomo 二进制与 Geodata 目录（便于秒级复用）。"""
    bins = []
    geo_dirs = []
    if os.path.isfile(MIHOMO_BIN):
        bins.append(MIHOMO_BIN)
    w = shutil.which("mihomo") or shutil.which("verge-mihomo")
    if w and os.path.isfile(w):
        bins.append(w)
    if os.name == "nt":
        win_cands = [
            r"D:\clash\Clash Verge\verge-mihomo.exe",
            r"C:\Program Files\Clash Verge\verge-mihomo.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Clash Verge\verge-mihomo.exe"),
            os.path.expandvars(r"%APPDATA%\huige-desktop\mihomo.exe"),
        ]
        for c in win_cands:
            if os.path.isfile(c) and c not in bins:
                bins.append(c)
        win_geos = [
            r"D:\clash\Clash Verge\resources",
            os.path.expandvars(r"%APPDATA%\io.github.clash-verge-rev.clash-verge-rev"),
            os.path.expandvars(r"%APPDATA%\com.follow\clash"),
        ]
        for g in win_geos:
            if os.path.isdir(g):
                geo_dirs.append(g)
    else:
        for c in ("/etc/mihomo/mihomo", "/usr/local/bin/mihomo", "/usr/bin/mihomo"):
            if os.path.isfile(c) and c not in bins:
                bins.append(c)
        for g in ("/etc/mihomo", "/usr/share/mihomo"):
            if os.path.isdir(g):
                geo_dirs.append(g)
    return bins, geo_dirs


def _ensure_mihomo_runtime_files():
    """确保 MIHOMO_DIR 下存在 config.yaml、providers/sub.yaml 及 Geodata 文件。"""
    os.makedirs(os.path.join(MIHOMO_DIR, "providers"), exist_ok=True)
    if not os.path.isfile(SUB_FILE):
        try:
            with open(SUB_FILE, "w", encoding="utf-8") as f:
                f.write("proxies: []\n")
        except OSError:
            pass
    if not os.path.isfile(CONFIG_FILE) and os.path.isfile(CONFIG_TPL_FILE):
        lan_ip = _outbound_lan_ip() or "127.0.0.1"
        try:
            with open(CONFIG_TPL_FILE, "r", encoding="utf-8") as f:
                tpl = f.read()
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(tpl.replace("__LAN_IP__", lan_ip))
        except OSError:
            pass
    # 若本地已有现成 Geodata 文件则自动补齐，避免首次启动阻塞下载
    _, geo_dirs = _find_local_mihomo_candidates()
    for fname in ("Country.mmdb", "country.mmdb", "geoip.dat", "geosite.dat", "ASN.mmdb"):
        dst = os.path.join(MIHOMO_DIR, fname)
        if os.path.isfile(dst):
            continue
        for gdir in geo_dirs:
            src = os.path.join(gdir, fname)
            if os.path.isfile(src):
                try:
                    shutil.copy2(src, dst)
                    break
                except OSError:
                    pass


def _binary_version(bin_path):
    """获取 mihomo 二进制版本号。"""
    if not bin_path or not os.path.isfile(bin_path):
        return ""
    rc, out = run('"%s" -v' % bin_path, timeout=5)
    if rc == 0 and out:
        return out.splitlines()[0].strip()
    return ""


def api_core_status():
    """检测本机 mihomo 核心安装状态、运行状态、平台架构及可用镜像源。"""
    sys_name, arch = _detect_os_arch()
    installed = os.path.isfile(MIHOMO_BIN)
    running = service_active("mihomo")
    ver_api = mihomo_api_safe("/version", timeout=2) or {}
    version = ver_api.get("version") or (_binary_version(MIHOMO_BIN) if installed else "")
    local_bins, _ = _find_local_mihomo_candidates()
    has_geo = any(os.path.isfile(os.path.join(MIHOMO_DIR, f)) for f in ("country.mmdb", "Country.mmdb", "geoip.dat"))

    if sys_name == "windows":
        asset_name = "mihomo-windows-%s-%s.zip" % (arch, MIHOMO_RELEASE_VER)
    elif sys_name == "darwin":
        asset_name = "mihomo-darwin-%s-%s.gz" % (arch, MIHOMO_RELEASE_VER)
    else:
        asset_name = "mihomo-linux-%s-%s.gz" % (arch, MIHOMO_RELEASE_VER)

    base_dl = "https://github.com/MetaCubeX/mihomo/releases/download/%s/%s" % (MIHOMO_RELEASE_VER, asset_name)
    mirrors = []
    for m in CORE_MIRRORS:
        mirrors.append({
            "id": m["id"],
            "name": m["name"],
            "url": m["prefix"] + base_dl,
        })
    if local_bins:
        mirrors.insert(0, {
            "id": "local",
            "name": "本机已检测到的核心 (%s · 秒级复用)" % os.path.basename(local_bins[0]),
            "url": local_bins[0],
        })

    return {
        "os": sys_name,
        "arch": arch,
        "installed": installed,
        "running": running,
        "version": version,
        "bin_path": MIHOMO_BIN,
        "config_ready": os.path.isfile(CONFIG_FILE),
        "geodata_ready": has_geo,
        "release_version": MIHOMO_RELEASE_VER,
        "asset_name": asset_name,
        "mirrors": mirrors,
    }


def _download_bytes(url, timeout=60):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (MihomoGatewayPanel/2.1)"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def api_core_install(mirror_id="auto"):
    """一键安装/修复 mihomo 核心（支持本机提取或从选定镜像源下载对应 Windows/Linux 版本并自动启动）。"""
    sys_name, arch = _detect_os_arch()
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    _ensure_mihomo_runtime_files()

    local_bins, _ = _find_local_mihomo_candidates()
    other_local = [b for b in local_bins if os.path.abspath(b) != os.path.abspath(MIHOMO_BIN)]

    # 停止正在运行的进程以便覆盖更新二进制
    if os.name == "nt" and _MIHOMO_PROC is not None:
        _stop_mihomo_proc()

    installed_from = ""
    errors = []

    # 1. 若选择 local 或 auto 且本机已有核心文件，直接复制安装
    if mirror_id in ("local", "auto") and (other_local or os.path.isfile(MIHOMO_BIN)):
        src = other_local[0] if other_local else MIHOMO_BIN
        try:
            if os.path.abspath(src) != os.path.abspath(MIHOMO_BIN):
                shutil.copy2(src, MIHOMO_BIN)
            if os.name != "nt":
                os.chmod(MIHOMO_BIN, 0o755)
            installed_from = "本机已有核心 (%s)" % src
        except Exception as e:  # noqa
            errors.append("本机复制失败: %s" % e)

    # 2. 从所选镜像源（或按序回退）联网下载对应平台与架构的官方包
    if not installed_from:
        if sys_name == "windows":
            asset_name = "mihomo-windows-%s-%s.zip" % (arch, MIHOMO_RELEASE_VER)
        elif sys_name == "darwin":
            asset_name = "mihomo-darwin-%s-%s.gz" % (arch, MIHOMO_RELEASE_VER)
        else:
            asset_name = "mihomo-linux-%s-%s.gz" % (arch, MIHOMO_RELEASE_VER)

        base_dl = "https://github.com/MetaCubeX/mihomo/releases/download/%s/%s" % (MIHOMO_RELEASE_VER, asset_name)
        cand_mirrors = [m for m in CORE_MIRRORS if m["id"] == mirror_id] if mirror_id not in ("auto", "local", "") else list(CORE_MIRRORS)
        if not cand_mirrors:
            cand_mirrors = list(CORE_MIRRORS)

        for m in cand_mirrors:
            dl_url = m["prefix"] + base_dl
            try:
                raw_bytes = _download_bytes(dl_url, timeout=90)
                tmp_bin = MIHOMO_BIN + ".new"
                if asset_name.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                        exe_members = [n for n in zf.namelist() if n.lower().endswith(".exe")]
                        if not exe_members:
                            raise ValueError("压缩包内未找到 .exe 文件")
                        with open(tmp_bin, "wb") as out_f:
                            out_f.write(zf.read(exe_members[0]))
                else:
                    decompressed = gzip.decompress(raw_bytes)
                    with open(tmp_bin, "wb") as out_f:
                        out_f.write(decompressed)
                if os.name != "nt":
                    os.chmod(tmp_bin, 0o755)
                os.replace(tmp_bin, MIHOMO_BIN)
                installed_from = m["name"]
                break
            except Exception as e:  # noqa
                errors.append("%s: %s" % (m["name"], e))

    if not installed_from or not os.path.isfile(MIHOMO_BIN):
        return {
            "ok": False,
            "msg": "核心安装失败：" + ("；".join(errors) or "无法下载"),
            "data": api_core_status(),
        }

    # 确保 Geodata 文件存在（若仍缺 country.mmdb 则尝试通过镜像下载）
    _ensure_mihomo_runtime_files()
    mmdb_path = os.path.join(MIHOMO_DIR, "country.mmdb")
    if not os.path.isfile(mmdb_path) and not os.path.isfile(os.path.join(MIHOMO_DIR, "Country.mmdb")):
        for m in CORE_MIRRORS:
            try:
                u = m["prefix"] + "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
                data = _download_bytes(u, timeout=45)
                if len(data) > 100000:
                    with open(mmdb_path, "wb") as f:
                        f.write(data)
                    break
            except Exception:  # noqa
                pass

    # 安装完成后立即启动 mihomo
    start_res = api_mihomo("restart")
    status = api_core_status()
    return {
        "ok": True,
        "msg": "mihomo 核心已安装就绪（来源：%s）并%s" % (
            installed_from, "已成功启动" if status.get("running") else start_res.get("msg", "尝试启动")
        ),
        "data": status,
    }


def _start_mihomo_proc():
    """直接以子进程方式启动 mihomo（适用于 Windows 及非 systemd 的 Linux 环境）。"""
    global _MIHOMO_PROC, _MIHOMO_LOG_FP
    if service_active("mihomo"):
        return True, "mihomo 已在运行中"
    _ensure_mihomo_runtime_files()
    if not os.path.isfile(MIHOMO_BIN):
        # 尝试自动从本机已有客户端提取
        cands, _ = _find_local_mihomo_candidates()
        if cands:
            try:
                shutil.copy2(cands[0], MIHOMO_BIN)
                if os.name != "nt":
                    os.chmod(MIHOMO_BIN, 0o755)
            except OSError:
                pass
    if not os.path.isfile(MIHOMO_BIN):
        return False, "未找到 mihomo 核心文件 (%s)，请先点击「一键安装核心」" % MIHOMO_BIN

    with _MIHOMO_PROC_LOCK:
        try:
            os.makedirs(MIHOMO_DIR, exist_ok=True)
            _MIHOMO_LOG_FP = open(MIHOMO_LOG_FILE, "a", encoding="utf-8", buffering=1)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            _MIHOMO_PROC = subprocess.Popen(
                [MIHOMO_BIN, "-d", MIHOMO_DIR],
                stdout=_MIHOMO_LOG_FP,
                stderr=subprocess.STDOUT,
                cwd=MIHOMO_DIR,
                creationflags=creationflags,
            )
        except Exception as e:  # noqa
            return False, "启动 mihomo 进程失败: %s" % e

    # 等待 API 端口就绪（最多 4 秒）
    for _ in range(16):
        time.sleep(0.25)
        if service_active("mihomo"):
            # 若面板中已保存选中节点，恢复选中
            with _STATE_LOCK:
                _load_state()
                sel = _STATE.get("selected_node") or ""
            if sel:
                mihomo_api_safe("/proxies/%s" % GROUP_NAME, method="PUT", payload={"name": sel}, timeout=3)
            return True, "mihomo 核心已启动 (API: %s)" % MIHOMO_API
    return False, "mihomo 进程已拉起但 9090 端口尚未就绪，请查看运行日志"


def _stop_mihomo_proc():
    """停止由面板托管或本机运行的 mihomo 进程。"""
    global _MIHOMO_PROC, _MIHOMO_LOG_FP
    with _MIHOMO_PROC_LOCK:
        if _MIHOMO_PROC is not None:
            try:
                _MIHOMO_PROC.terminate()
                _MIHOMO_PROC.wait(timeout=4)
            except Exception:  # noqa
                try:
                    _MIHOMO_PROC.kill()
                except Exception:  # noqa
                    pass
            _MIHOMO_PROC = None
        if _MIHOMO_LOG_FP is not None:
            try:
                _MIHOMO_LOG_FP.close()
            except Exception:  # noqa
                pass
            _MIHOMO_LOG_FP = None
    if os.name == "nt":
        run("taskkill /F /IM mihomo.exe", timeout=5)
    else:
        run("pkill -f '%s'" % MIHOMO_BIN, timeout=5)
    return True, "mihomo 核心已停止"


def api_mihomo(action):
    """跨平台 mihomo 服务启停控制（Linux systemd + Windows/通用进程双支持）。"""
    if action not in ("start", "stop", "restart"):
        return {"ok": False, "msg": "不支持的操作"}
    _ensure_mihomo_runtime_files()
    # Linux 下若配置了 systemd unit 则优先走 systemctl
    if os.name != "nt" and os.path.isfile("/etc/systemd/system/mihomo.service"):
        rc, out = run("systemctl %s mihomo" % action, timeout=60)
        if rc == 0:
            return {"ok": True, "msg": out or ("mihomo %s 已执行" % action)}
    if action == "stop":
        ok, msg = _stop_mihomo_proc()
        return {"ok": ok, "msg": msg}
    if action == "restart":
        _stop_mihomo_proc()
        time.sleep(0.3)
        ok, msg = _start_mihomo_proc()
        return {"ok": ok, "msg": msg}
    ok, msg = _start_mihomo_proc()
    return {"ok": ok, "msg": msg}


def _is_tproxy_or_sysproxy_on():
    """检测透明代理（Linux iptables）或系统代理（Windows 注册表）是否已启用。"""
    if os.name != "nt":
        if os.path.isfile(TPROXY_SH):
            _, out = run("bash %s status" % TPROXY_SH, timeout=6)
            return ("MIHOMO_REDIR" in out and "未启用" not in out) or ("TPROXY_STATE=on" in out)
        return False
    _, out = run(r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable', timeout=4)
    return "0x1" in out


def _win_ip_forwarding():
    """检测 Windows 出网网卡是否已开启 IP 转发（作为网关的必要条件）。"""
    _, out = run('powershell -NoProfile -Command "Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,Forwarding | ConvertTo-Json -Compress"', timeout=8)
    if not out:
        return False
    return '"Forwarding":1' in out.replace(" ", "") or '"Forwarding": 1' in out


def _win_firewall_gateway_ready():
    """检测是否已存在 HomeWifiVPN 的防火墙放行规则。"""
    _, out = run('powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName \'HomeWifiVPN*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"', timeout=8)
    try:
        return int(out.strip() or "0") > 0
    except ValueError:
        return False


def api_gateway_status():
    """检测本机作为旁路网关的可用性（Windows 与 Linux 通用）。"""
    net = api_network()
    lan_ip = net.get("lan_ip", "")
    core = api_core_status()
    proxy_listening = False
    _, out = run("netstat -ano" if os.name == "nt" else "ss -ltn", timeout=5)
    proxy_listening = bool(re.search(r":%d\s" % MIXED_PORT, out))

    if os.name == "nt":
        forwarding = _win_ip_forwarding()
        fw_ready = _win_firewall_gateway_ready()
        script = os.path.join(PROJECT_DIR, "scripts", "win-gateway.ps1")
        return {
            "platform": "windows",
            "mode": "windows-proxy-only",
            "transparent_supported": False,
            "lan_ip": lan_ip,
            "core_installed": core.get("installed", False),
            "core_running": core.get("running", False),
            "ip_forwarding": forwarding,
            "firewall_ready": fw_ready,
            "proxy_listening": proxy_listening,
            "proxy_port": MIXED_PORT,
            "dns_port": 53,
            "gateway_ready": False,
            "needs_admin": False,
            "helper_script": script,
            "helper_cmd": 'powershell -ExecutionPolicy Bypass -File "%s" -Action on' % script,
            "proxy_ready": bool(core.get("running") and proxy_listening),
            "recommend": "proxy-direct",
            "note": "Windows 无 iptables/TProxy，无法做透明网关；请让局域网设备直接使用代理 %s:%d" % (lan_ip, MIXED_PORT),
        }
    tproxy_on = _is_tproxy_or_sysproxy_on()
    return {
        "platform": "linux",
        "mode": "linux-tproxy" if tproxy_on else "linux-no-tproxy",
        "transparent_supported": True,
        "lan_ip": lan_ip,
        "core_installed": core.get("installed", False),
        "core_running": core.get("running", False),
        "ip_forwarding": tproxy_on,
        "firewall_ready": tproxy_on,
        "proxy_listening": proxy_listening,
        "proxy_port": MIXED_PORT,
        "dns_port": 53,
        "gateway_ready": bool(tproxy_on and core.get("running")),
        "needs_admin": False,
        "helper_script": TPROXY_SH,
        "helper_cmd": "bash %s start" % TPROXY_SH,
        "proxy_ready": bool(core.get("running") and proxy_listening),
        "recommend": "gateway",
    }


def api_gateway_enable():
    """一键把本机配置为旁路网关（Windows 调 PowerShell 提权脚本；Linux 启 tproxy）。"""
    if os.name == "nt":
        script = os.path.join(PROJECT_DIR, "scripts", "win-gateway.ps1")
        if not os.path.isfile(script):
            return {"ok": False, "msg": "未找到 Windows 网关脚本 scripts/win-gateway.ps1"}
        # 以管理员身份弹出 UAC 执行（需要用户在弹窗中确认）
        cmd = ('powershell -NoProfile -Command "Start-Process powershell -Verb RunAs '
               '-ArgumentList \'-ExecutionPolicy Bypass -File \\"%s\\" -Action on\'"' % script)
        rc, out = run(cmd, timeout=20)
        return {
            "ok": True,
            "msg": "已请求管理员权限配置网关；请在 Windows 弹出的 UAC 窗口中点击「是」，完成后点「重新检测」。",
            "detail": out[-300:],
        }
    if not os.path.isfile(TPROXY_SH):
        return {"ok": False, "msg": "未找到 %s" % TPROXY_SH}
    rc, out = run("bash %s start" % TPROXY_SH, timeout=60)
    return {"ok": rc == 0, "msg": out or "透明代理已启动"}


def api_tproxy(action):
    """跨平台代理转发控制：Linux 下启停 iptables TProxy；Windows 下启停本机系统代理 (127.0.0.1:7890)。"""
    if action not in ("start", "stop"):
        return {"ok": False, "msg": "不支持的操作"}
    if os.name != "nt":
        if not os.path.isfile(TPROXY_SH):
            return {"ok": False, "msg": "未找到 %s，请先运行 install.sh" % TPROXY_SH}
        rc, out = run("bash %s %s" % (TPROXY_SH, action), timeout=60)
        return {"ok": rc == 0, "msg": out or ("透明代理 %s 已执行" % action)}
    # Windows：若启用则先确保 mihomo 正在运行，再设置系统代理到 127.0.0.1:7890
    if action == "start":
        if not service_active("mihomo"):
            _start_mihomo_proc()
        reg_key = r'"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"'
        run('reg add %s /v ProxyEnable /t REG_DWORD /d 1 /f' % reg_key, timeout=5)
        run('reg add %s /v ProxyServer /t REG_SZ /d "127.0.0.1:%d" /f' % (reg_key, MIXED_PORT), timeout=5)
        return {"ok": True, "msg": "已启用系统代理转发 (127.0.0.1:%d) 并开放局域网网关接入" % MIXED_PORT}
    else:
        reg_key = r'"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"'
        run('reg add %s /v ProxyEnable /t REG_DWORD /d 0 /f' % reg_key, timeout=5)
        return {"ok": True, "msg": "已停用本机系统代理转发"}


# ============================================================
# TUN 模式（Windows 整机透明代理）状态检测与安全开关
# ============================================================
def _read_tun_enabled():
    """从 config.yaml 读取 tun.enable 状态。"""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return False
    in_tun = False
    for line in lines:
        if re.match(r"^tun\s*:", line):
            in_tun = True
            continue
        if in_tun:
            if re.match(r"^\S", line):
                break
            m = re.match(r"^\s+enable\s*:\s*(true|false)", line, re.I)
            if m:
                return m.group(1).lower() == "true"
    return False


def _write_tun_enabled(enabled):
    """改写 config.yaml 中 tun.enable 的值（保持其它行不变）。"""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return False
    out = []
    in_tun = False
    tun_seen = False
    wrote = False
    for line in lines:
        if re.match(r"^tun\s*:", line):
            in_tun = True
            tun_seen = True
            out.append(line)
            continue
        if in_tun:
            if re.match(r"^\S", line):
                if not wrote:
                    out.append("  enable: %s" % ("true" if enabled else "false"))
                    wrote = True
                in_tun = False
                out.append(line)
                continue
            if re.match(r"^\s+enable\s*:", line):
                out.append("  enable: %s" % ("true" if enabled else "false"))
                wrote = True
                continue
        out.append(line)
    if not tun_seen:
        out.extend([
            "",
            "tun:",
            "  enable: %s" % ("true" if enabled else "false"),
            "  stack: gvisor",
            "  auto-route: true",
            "  auto-detect-interface: true",
            "  dns-hijack:",
            "    - any:53",
        ])
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")
        return True
    except OSError:
        return False


def _tun_adapter_present():
    """检测系统是否存在 mihomo 创建的 TUN 虚拟网卡。"""
    if os.name != "nt":
        _, out = run("ip link show", timeout=4)
        return bool(re.search(r"(Mihomo|meta|utun|tun\d)", out))
    _, out = run('powershell -NoProfile -Command "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match \'WinTun|Mihomo|Meta\' } | Select-Object -ExpandProperty Name"', timeout=8)
    return bool(out.strip())


def _port_conflicts():
    """检测会与 mihomo 冲突的其它代理软件（Clash Verge 等）。"""
    conflicts = []
    _, out = run("tasklist", timeout=6)
    low = out.lower()
    if "verge-mihomo" in low:
        conflicts.append("Clash Verge (verge-mihomo)")
    if "clash-win64" in low or "clash-windows" in low:
        conflicts.append("Clash for Windows")
    if "v2ray" in low or "sing-box" in low or "singbox" in low:
        conflicts.append("其它代理核心 (v2ray/sing-box)")
    return conflicts


def api_tun_status():
    """TUN 模式状态：是否启用、依赖是否就绪、潜在冲突。"""
    enabled = _read_tun_enabled()
    wintun = os.path.isfile(os.path.join(MIHOMO_DIR, "wintun.dll"))
    adapter = _tun_adapter_present()
    conflicts = _port_conflicts()
    admin = True
    if os.name == "nt":
        _, out = run('powershell -NoProfile -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"', timeout=6)
        admin = out.strip().lower().startswith("true")
    reasons = []
    if not wintun:
        reasons.append("缺少 wintun.dll（TUN 驱动），请点击「修复依赖」自动获取")
    if conflicts:
        reasons.append("检测到冲突程序：%s，会抢占端口导致核心启动失败，建议先退出" % "、".join(conflicts))
    return {
        "supported": os.name == "nt" or os.name != "nt",
        "platform": "windows" if os.name == "nt" else "linux",
        "enabled": enabled,
        "active": enabled and adapter,
        "wintun_ready": wintun,
        "adapter_present": adapter,
        "is_admin": admin,
        "conflicts": conflicts,
        "blockers": reasons,
        "ready": bool(wintun and not conflicts),
    }


def api_tun_set(enabled):
    """开启/关闭 TUN 模式并重启核心。"""
    if enabled and not os.path.isfile(os.path.join(MIHOMO_DIR, "wintun.dll")):
        return {"ok": False, "msg": "缺少 wintun.dll，请先点击「修复依赖」", "data": api_tun_status()}
    if not _write_tun_enabled(enabled):
        return {"ok": False, "msg": "写入 config.yaml 失败", "data": api_tun_status()}
    res = api_mihomo("restart")
    time.sleep(1)
    st = api_tun_status()
    if enabled and not st["active"]:
        return {
            "ok": False,
            "msg": "已写入 TUN 配置，但虚拟网卡未创建。%s 请查看运行日志。" % (
                "可能原因：" + "；".join(st["blockers"]) if st["blockers"] else ""
            ),
            "data": st,
        }
    return {"ok": True, "msg": "TUN 模式已%s" % ("开启" if enabled else "关闭"), "data": st}


def api_tun_fix():
    """修复 TUN 依赖：从本机已安装的代理软件中提取 wintun.dll。"""
    dst = os.path.join(MIHOMO_DIR, "wintun.dll")
    if os.path.isfile(dst):
        return {"ok": True, "msg": "wintun.dll 已存在，无需修复", "data": api_tun_status()}
    candidates = []
    if os.name == "nt":
        for root in (r"D:\clash\Clash Verge\resources", r"C:\Program Files\Clash Verge\resources",
                     os.path.expandvars(r"%APPDATA%\io.github.clash-verge-rev.clash-verge-rev"),
                     r"D:\uu\Netease\UU\5248\wintun"):
            if os.path.isdir(root):
                candidates.append(os.path.join(root, "wintun.dll"))
    _, out = run('powershell -NoProfile -Command "Get-ChildItem -Path C:\\,D:\\ -Filter wintun.dll -Recurse -ErrorAction SilentlyContinue -Depth 6 | Select-Object -First 5 -ExpandProperty FullName"', timeout=40)
    for line in out.splitlines():
        p = line.strip()
        if p and p.lower().endswith("wintun.dll"):
            candidates.append(p)
    for src in candidates:
        if os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
                return {"ok": True, "msg": "已从 %s 提取 wintun.dll" % src, "data": api_tun_status()}
            except OSError:
                continue
    # 兜底：从官方 wintun 镜像下载
    for m in CORE_MIRRORS:
        try:
            u = m["prefix"] + "https://www.wintun.net/builds/wintun-0.14.1.zip"
            raw = _download_bytes(u, timeout=45)
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for n in zf.namelist():
                    if n.lower().endswith("amd64/wintun.dll"):
                        with open(dst, "wb") as f:
                            f.write(zf.read(n))
                        return {"ok": True, "msg": "已从镜像下载 wintun.dll", "data": api_tun_status()}
        except Exception:  # noqa
            continue
    return {"ok": False, "msg": "未能自动获取 wintun.dll，请手动放置到 %s" % MIHOMO_DIR, "data": api_tun_status()}


def api_logs(lines=120):
    try:
        lines = max(10, min(int(lines), 500))
    except (TypeError, ValueError):
        lines = 120
    net = api_network()
    sub = api_subscription_get()
    core = api_core_status()
    header = [
        "[%s] 面板运行中 | 平台: %s/%s | 数据目录: %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), core["os"], core["arch"], MIHOMO_DIR
        ),
        "[%s] 本机局域网: %s (%s) | 公网出口: %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), net.get("lan_ip") or "-", net.get("lan_if") or "-", net.get("public_ip") or "-"
        ),
        "[%s] 订阅状态: 已配置 %d 个订阅（启用 %d 个），共 %d 个真实节点" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), sub.get("total_subs", 0), sub.get("enabled_subs", 0), sub.get("nodes", 0)
        ),
        "[%s] mihomo API (%s): %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S"),
            MIHOMO_API,
            ("在线 (%s)" % (core.get("version") or "running")) if core.get("running") else "未检测到运行（可在仪表盘点击「一键安装/启动核心」）",
        ),
    ]
    tail_lines = []
    if os.path.isfile(MIHOMO_LOG_FILE):
        try:
            with open(MIHOMO_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                tail_lines = f.read().splitlines()[-lines:]
        except OSError:
            pass
    elif os.name != "nt":
        rc, out = run("journalctl -u mihomo --no-pager -n %d" % lines, timeout=10)
        if rc == 0 and out:
            tail_lines = out.splitlines()
    if tail_lines:
        header.append("--- mihomo 实时引擎日志 ---")
        header.extend(tail_lines)
    return {"logs": "\n".join(header)}


# ============================================================
# HTTP 服务处理
# ============================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "MihomoGatewayPanel/2.1"

    def _send_json(self, code, obj, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            self._send_json(404, {"ok": False, "msg": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return bool(CONF.get("token")) and self.headers.get("X-Token", "") == CONF.get("token")

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _query(self, key, default=""):
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        m = re.search(r"(?:^|&)%s=([^&]*)" % re.escape(key), qs)
        if not m:
            return default
        return urllib.parse.unquote(m.group(1))

    def log_message(self, fmt, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-Token, Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
            return
        if path == "/setup":
            self._send_file(os.path.join(STATIC_DIR, "setup.html"), "text/html; charset=utf-8")
            return
        if path == "/api/network":
            try:
                self._send_json(200, {"ok": True, "data": api_network()})
            except Exception as e:  # noqa
                self._send_json(500, {"ok": False, "msg": str(e)})
            return
        if path == "/api/connecttest":
            try:
                client_ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
                self._send_json(200, {"ok": True, "data": api_connecttest(client_ip)},
                                extra_headers={"Access-Control-Allow-Origin": "*"})
            except Exception as e:  # noqa
                self._send_json(500, {"ok": False, "msg": str(e)},
                                extra_headers={"Access-Control-Allow-Origin": "*"})
            return

        if not path.startswith("/api/"):
            self._send_json(404, {"ok": False, "msg": "not found"})
            return
        if not self._authed():
            self._send_json(401, {"ok": False, "msg": "未授权，请先登录"})
            return

        try:
            if path == "/api/overview":
                self._send_json(200, {"ok": True, "data": api_overview()})
            elif path == "/api/proxies":
                self._send_json(200, {"ok": True, "data": api_proxies()})
            elif path == "/api/clients":
                self._send_json(200, {"ok": True, "data": api_clients()})
            elif path == "/api/health":
                self._send_json(200, {"ok": True, "data": api_health()})
            elif path == "/api/nodehistory":
                self._send_json(200, api_nodehistory(self._query("name", "")))
            elif path == "/api/subscription":
                self._send_json(200, {"ok": True, "data": api_subscription_get()})
            elif path == "/api/core":
                self._send_json(200, {"ok": True, "data": api_core_status()})
            elif path == "/api/gateway":
                self._send_json(200, {"ok": True, "data": api_gateway_status()})
            elif path == "/api/tun":
                self._send_json(200, {"ok": True, "data": api_tun_status()})
            elif path == "/api/logs":
                lines = 120
                try:
                    lines = int(self._query("lines", "120"))
                except ValueError:
                    pass
                self._send_json(200, {"ok": True, "data": api_logs(lines)})
            else:
                self._send_json(404, {"ok": False, "msg": "未知接口"})
        except Exception as e:  # noqa
            self._send_json(500, {"ok": False, "msg": str(e)})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if not path.startswith("/api/"):
            self._send_json(404, {"ok": False, "msg": "not found"})
            return
        if path == "/api/login":
            body = self._read_body()
            ok = bool(CONF.get("token")) and body.get("token", "") == CONF.get("token", "")
            self._send_json(200, {"ok": ok, "msg": "" if ok else "口令错误"})
            return
        if not self._authed():
            self._send_json(401, {"ok": False, "msg": "未授权，请先登录"})
            return

        body = self._read_body()
        try:
            if path == "/api/select":
                self._send_json(200, api_select(body.get("name", "")))
            elif path == "/api/healthcheck":
                self._send_json(200, api_healthcheck())
            elif path == "/api/autoselect":
                self._send_json(200, api_autoselect(body.get("strategy", "fastest")))
            elif path == "/api/favorite":
                self._send_json(200, api_favorite(body.get("name", "")))
            elif path == "/api/subscription":
                self._send_json(200, api_subscription_set(body))
            elif path == "/api/subscription/refresh":
                self._send_json(200, api_subscription_refresh(body.get("id") or None))
            elif path == "/api/subscription/toggle":
                self._send_json(200, api_subscription_toggle(body.get("id", ""), body.get("enabled")))
            elif path == "/api/subscription/delete":
                self._send_json(200, api_subscription_delete(body.get("id", "")))
            elif path == "/api/subscription/update":
                self._send_json(200, api_subscription_update(body.get("id", ""), body.get("name", ""), body.get("url", "")))
            elif path == "/api/core/install":
                self._send_json(200, api_core_install(body.get("mirror", "auto")))
            elif path == "/api/gateway/enable":
                self._send_json(200, api_gateway_enable())
            elif path == "/api/tun/set":
                self._send_json(200, api_tun_set(bool(body.get("enabled"))))
            elif path == "/api/tun/fix":
                self._send_json(200, api_tun_fix())
            elif path == "/api/mihomo":
                self._send_json(200, api_mihomo(body.get("action", "")))
            elif path == "/api/tproxy":
                self._send_json(200, api_tproxy(body.get("action", "")))
            else:
                self._send_json(404, {"ok": False, "msg": "未知接口"})
        except Exception as e:  # noqa
            self._send_json(500, {"ok": False, "msg": str(e)})


def main():
    port = CONF["port"]
    os.makedirs(MIHOMO_DIR, exist_ok=True)
    _ensure_mihomo_runtime_files()
    # 注意：默认【不】自动启动 mihomo 核心。
    # 原因：本机可能已运行其它代理软件（Clash Verge 等），自动拉起会抢占
    # 7890/9090/53 端口并干扰其正常工作。需要时请在面板「核心」卡片手动点击启动。
    if os.environ.get("MIHOMO_AUTOSTART", "").strip().lower() in ("1", "true", "yes", "on"):
        if os.path.isfile(MIHOMO_BIN) and not service_active("mihomo"):
            ok, msg = _start_mihomo_proc()
            print("[core] %s" % msg)
        else:
            print("[core] 已跳过自动启动（MIHOMO_AUTOSTART 已开启但核心已在运行或缺失）")
    else:
        print("[core] 未自动启动 mihomo（默认行为，避免与其它代理软件抢端口；如需自动启动请设 MIHOMO_AUTOSTART=1）")
    if not CONF.get("token"):
        print("[warn] panel.conf 中未设置 token，接口将全部拒绝访问，请先配置 token")
    start_speed_sampler()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("mihomo 旁路网关面板（真实数据模式）已启动: http://0.0.0.0:%d (数据目录: %s)" % (port, MIHOMO_DIR))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
