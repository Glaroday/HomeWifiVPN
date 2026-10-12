#!/bin/bash
# ============================================================
# mihomo 多订阅更新与合并脚本
# 用法:
#   1. 把一个或多个订阅链接写入 /etc/mihomo/subscribe_url.txt
#      支持格式（一行一条）:
#        https://example.com/sub?token=xxx
#        主力机场|https://example.com/sub?token=xxx
#   2. 执行 /etc/mihomo/update-sub.sh
# 说明:
#   - 订阅 token 全程不落对话/日志，只在本机文件间流转
#   - 多订阅时自动拉取合并 proxies 段并给节点加上 [订阅名] 标识、自动处理重名
# ============================================================
set -e
URL_FILE="${MIHOMO_DIR:-/etc/mihomo}/subscribe_url.txt"
SUB_FILE="${MIHOMO_DIR:-/etc/mihomo}/providers/sub.yaml"
TMP_DIR="$(mktemp -d /tmp/mihomo_sub.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [ ! -f "$URL_FILE" ]; then
  echo "❌ 未找到订阅文件 $URL_FILE"
  exit 1
fi

mapfile -t LINES < <(grep -vE '^\s*(#|$)' "$URL_FILE" 2>/dev/null | sed 's/\r$//' || true)
TOTAL="${#LINES[@]}"
if [ "$TOTAL" -eq 0 ]; then
  echo "❌ 请先把订阅链接写入 $URL_FILE（支持多行，每行一条 URL 或 名称|URL）"
  exit 1
fi

echo "发现 ${TOTAL} 个启用中的订阅源，开始拉取（链接已隐藏）..."
OK_COUNT=0
IDX=0

for RAW in "${LINES[@]}"; do
  IDX=$((IDX + 1))
  if [[ "$RAW" == *"|"* ]]; then
    NAME="${RAW%%|*}"
    URL="${RAW#*|}"
  else
    NAME="订阅${IDX}"
    URL="$RAW"
  fi
  URL="$(printf '%s' "$URL" | tr -d '\r\n[:space:]')"
  [ -n "$URL" ] || continue

  OUT_FILE="$TMP_DIR/sub_${IDX}.yaml"
  NAME_FILE="$TMP_DIR/sub_${IDX}.name"
  printf '%s' "$NAME" > "$NAME_FILE"

  if curl -fsSL --connect-timeout 15 -m 90 -A "clash.meta/v1.19.32" -o "$OUT_FILE" "$URL" 2>/dev/null; then
    if grep -q "proxies" "$OUT_FILE" 2>/dev/null; then
      OK_COUNT=$((OK_COUNT + 1))
      echo "  ✓ [${NAME}] 拉取成功"
    else
      echo "  ⚠ [${NAME}] 返回内容不含 proxies 字段，已跳过"
      rm -f "$OUT_FILE"
    fi
  else
    echo "  ⚠ [${NAME}] 拉取失败，已跳过"
    rm -f "$OUT_FILE"
  fi
done

if [ "$OK_COUNT" -eq 0 ]; then
  echo "❌ 所有订阅均拉取失败或格式无效，未覆盖原节点文件"
  exit 1
fi

# 使用 Python3 合并多个订阅的 proxies 块（单订阅直接原样保留，多订阅合并并按需加前缀防重名）
python3 - "$TMP_DIR" "${SUB_FILE}.new" "$OK_COUNT" <<'PYEOF'
import glob, os, re, sys

tmp_dir, out_path, ok_count = sys.argv[1], sys.argv[2], int(sys.argv[3])
files = sorted(glob.glob(os.path.join(tmp_dir, "sub_*.yaml")))

if len(files) == 1:
    with open(files[0], "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    sys.exit(0)

merged_lines = ["proxies:"]
seen_names = set()

for yf in files:
    nf = yf[:-5] + ".name"
    sub_name = "订阅"
    if os.path.isfile(nf):
        with open(nf, "r", encoding="utf-8", errors="replace") as f:
            sub_name = f.read().strip() or "订阅"
    with open(yf, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    in_proxies = False
    for line in lines:
        if re.match(r"^proxies\s*:", line):
            in_proxies = True
            continue
        if in_proxies:
            if re.match(r"^[A-Za-z0-9_-]+\s*:", line):
                break
            if re.match(r"^\s*-\s+", line):
                # 给节点名加上 [订阅名] 前缀（若尚未带前缀）
                def repl(m):
                    prefix, q, nm = m.group(1), m.group(2), m.group(3)
                    clean = nm.strip()
                    if not clean.startswith("["):
                        clean = "[%s] %s" % (sub_name, clean)
                    base = clean
                    k = 2
                    while clean in seen_names:
                        clean = "%s #%d" % (base, k)
                        k += 1
                    seen_names.add(clean)
                    return "%s%s%s%s" % (prefix, q, clean, q)
                line = re.sub(r"(name\s*:\s*)(['\"]?)([^,'\"}\n]+)\2", repl, line, count=1)
            merged_lines.append(line)

with open(out_path, "w", encoding="utf-8") as f:
    f.write("\n".join(merged_lines) + "\n")
PYEOF

mkdir -p "$(dirname "$SUB_FILE")"
mv "${SUB_FILE}.new" "$SUB_FILE"
systemctl restart mihomo 2>/dev/null || true
sleep 2

NODES=$(grep -cE "^\s*-.*name" "$SUB_FILE" || true)
echo "✅ 已合并 ${OK_COUNT}/${TOTAL} 个订阅并重启 mihomo（共 ${NODES} 个节点）"

# ---- 各地区节点数摘要（尽力而为，失败不影响主流程）----
count_region() {
  local n
  n=$(grep -oiE "$1" "$SUB_FILE" 2>/dev/null | wc -l || true)
  echo "${n:-0}"
}
HK=$(count_region '香港|HK|Hong ?Kong')
JP=$(count_region '日本|JP|Japan')
SG=$(count_region '新加坡|狮城|SG|Singapore')
US=$(count_region '美国|US|United ?States')
KR=$(count_region '韩国|KR|Korea')
TW=$(count_region '台湾|台|TW|Taiwan')
echo "节点分布: 香港 x$HK | 日本 x$JP | 新加坡 x$SG | 美国 x$US | 韩国 x$KR | 台湾 x$TW"
