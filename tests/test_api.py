#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HomeWifiVPN 全真实模式集成测试（无任何 Mock 假数据）。
测试流程：
  1. 启动一个本地临时 HTTP 订阅源（模拟真实机场返回 Clash YAML 节点与 Base64 节点，节点指向本机测试端口）
  2. 启动真实面板后端 app/server.py
  3. 逐项验证：鉴权、本机真实网络探测、终端连接自测、多订阅真实 HTTP 拉取/解析/TCP 测速/切换/收藏、真实体检、日志等。
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "app", "server.py")
PORT = 18899
SUB_SERVER_PORT = 18900
BASE = "http://127.0.0.1:%d" % PORT

FAILS = []
PASSES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print("  PASS  %s" % name)
    else:
        FAILS.append("%s %s" % (name, detail))
        print("  FAIL  %s  %s" % (name, detail))


def req(path, method="GET", body=None, token=None, timeout=15):
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("X-Token", token)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"_err": str(e)}


def get_token():
    conf = os.path.join(ROOT, "panel.conf")
    with open(conf, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("token="):
                return line.split("=", 1)[1]
    return ""


class _LocalSubFeedHandler(BaseHTTPRequestHandler):
    """提供本地真实可拉取的 Clash YAML 与 Base64 订阅内容，节点指向 127.0.0.1:PORT 以便实测 TCP 握手延迟。"""
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/sub1"):
            yaml_body = (
                "proxies:\n"
                "  - {name: \"香港-IEPL-01\", type: ss, server: 127.0.0.1, port: %d, udp: true}\n"
                "  - {name: \"日本-东京-01\", type: trojan, server: 127.0.0.1, port: %d, udp: true}\n"
            ) % (PORT, PORT)
            raw = yaml_body.encode("utf-8")
        else:
            uris = "\n".join([
                "trojan://pass@127.0.0.1:%d#%s" % (PORT, urllib.parse.quote("新加坡-BGP-01")),
                "ss://YWVzLTI1Ni1nY206cGFzcw==@127.0.0.1:%d#%s" % (PORT, urllib.parse.quote("美国-洛杉矶-01")),
            ])
            raw = base64.b64encode(uris.encode("utf-8"))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    token = get_token()
    tmp_dir = tempfile.mkdtemp(prefix="mihomo_real_test_")
    test_conf = os.path.join(tmp_dir, "panel.conf")
    with open(test_conf, "w", encoding="utf-8") as f:
        f.write("port=%d\ntoken=%s\n" % (PORT, token))

    sub_httpd = HTTPServer(("127.0.0.1", SUB_SERVER_PORT), _LocalSubFeedHandler)
    sub_thread = threading.Thread(target=sub_httpd.serve_forever, daemon=True)
    sub_thread.start()

    env = dict(os.environ, MIHOMO_DIR=tmp_dir, PANEL_CONF=test_conf)
    env.pop("MIHOMO_MOCK", None)

    print("[test] 启动真实模式后端 (port %d)..." % PORT)
    proc = subprocess.Popen([sys.executable, SERVER], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        ok = False
        for _ in range(40):
            time.sleep(0.3)
            code, _ = req("/api/login", "POST", {"token": token})
            if code == 200:
                ok = True
                break
        if not ok:
            print("[test] 后端未就绪")
            return 2
        run_suite(token)
    finally:
        sub_httpd.shutdown()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print("\n[test] %d passed, %d failed" % (len(PASSES), len(FAILS)))
    for f in FAILS:
        print("   FAILED: %s" % f)
    return 0 if not FAILS else 1


def run_suite(token):
    print("\n== 鉴权 ==")
    code, _ = req("/api/overview")
    check("无token overview 返回401", code == 401)
    code, j = req("/api/login", "POST", {"token": token})
    check("正确token login ok", code == 200 and j.get("ok") is True)

    print("\n== 真实网关探测 (/api/network) ==")
    code, j = req("/api/network")
    d = j.get("data", {})
    check("network 200 ok", code == 200 and j.get("ok") is True)
    check("真实本机局域网 IP 已探测", bool(d.get("lan_ip")), str(d.get("lan_ip")))
    check("suggested_client 四要素齐全", all(k in d.get("suggested_client", {}) for k in ("ip", "netmask", "gateway", "dns")))

    print("\n== 真实连接判定 (/api/connecttest) ==")
    code, j = req("/api/connecttest")
    d = j.get("data", {})
    check("connecttest 200 ok", code == 200 and j.get("ok") is True)
    check("connecttest verdict 合法", d.get("verdict") in ("connected", "partial", "not_connected"), str(d.get("verdict")))

    print("\n== 多订阅真实拉取、解析与 TCP 测速 ==")
    sub1 = "主力机场|http://127.0.0.1:%d/sub1?token=real_secret_1" % SUB_SERVER_PORT
    sub2 = "备用机场|http://127.0.0.1:%d/sub2?key=real_secret_2" % SUB_SERVER_PORT
    code, j = req("/api/subscription", "POST", {"url": sub1 + "\n" + sub2, "mode": "replace"}, token)
    check("批量拉取2个真实订阅成功", code == 200 and j.get("ok") is True, str(j))
    sdata = j.get("data", {})
    check("订阅数 == 2 且节点数 == 4", sdata.get("total_subs") == 2 and sdata.get("nodes") == 4, str(sdata))
    check("订阅 URL 自动脱敏", "***" in sdata.get("url", ""), sdata.get("url", ""))

    print("\n== 真实节点列表与实测延迟 (/api/proxies) ==")
    code, j = req("/api/proxies", token=token)
    pdata = j.get("data", {})
    stats = pdata.get("stats", {})
    check("节点总数 == 4 且全部实测 TCP 连通", stats.get("total") == 4 and stats.get("alive") == 4, str(stats))

    code, j = req("/api/autoselect", "POST", {"strategy": "fastest"}, token)
    check("autoselect fastest 成功", j.get("ok") is True and j.get("data", {}).get("name"), str(j))

    code, j = req("/api/healthcheck", "POST", {}, token)
    check("真实 TCP 批量测速成功", j.get("ok") is True, str(j))

    print("\n== 真实客户端与系统体检 (/api/clients & /api/health) ==")
    code, j = req("/api/clients", token=token)
    check("clients 正常返回", code == 200 and isinstance(j.get("data", {}).get("clients"), list))
    code, j = req("/api/health", token=token)
    hdata = j.get("data", {})
    check("health 9项指标齐全", len(hdata.get("checks") or []) == 9 and 0 <= hdata.get("score", -1) <= 100)


if __name__ == "__main__":
    sys.exit(main())
