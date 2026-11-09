#!/usr/bin/env bash
# 端到端验收：启动界面、填入真实参数、点「开始解密」，
# 然后比对输出目录和原始明文是否逐字节一致。
#
# 需要先有 rclone 生成的样本（见 tools/verify.sh）。
set -u

export PATH="$PATH:$(go env GOPATH)/bin"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="C:/Users/withu/AppData/Local/Temp/alist.sock"
BASE="C:/Users/withu/AppData/Local/Temp/crypt64"
ENC="$BASE/enc"
OUT="$BASE/out"
PLAIN="$BASE/plain"
SHOT="${1:-C:/Users/withu/AppData/Local/Temp/e2e.png}"
PW="test-password-123"
SALT="test-salt-456"
EXPECTED=$(find "$PLAIN" -type f | wc -l)

cd "$ROOT" || exit 1

mygo-automation close >/dev/null 2>&1
rm -rf "$OUT"
mkdir -p "$OUT"

go build -tags e2e -o /tmp/alistcrypt-e2e.exe . || exit 1

MYGO_AUTOMATION="$SOCK" /tmp/alistcrypt-e2e.exe >/tmp/alist-app.log 2>&1 &
APP_PID=$!
sleep 3

mygo-automation open --socket "$SOCK" >/dev/null || { echo "无法连接应用"; kill "$APP_PID" 2>/dev/null; exit 1; }

mygo-automation fill key=src "$ENC" >/dev/null
mygo-automation fill key=dst "$OUT" >/dev/null
mygo-automation fill key=pw "$PW" >/dev/null
mygo-automation fill key=salt "$SALT" >/dev/null
sleep 1.5

BTN=$(mygo-automation snapshot -i | grep 'button.*"开始解密"' | head -1 | awk '{print $1}')
if [ -z "$BTN" ]; then
  echo "找不到开始按钮"
  mygo-automation screenshot "$SHOT" >/dev/null
  kill "$APP_PID" 2>/dev/null
  exit 1
fi
mygo-automation press "$BTN" >/dev/null

# 轮询输出目录，最多等 30 秒
for _ in $(seq 1 60); do
  n=$(find "$OUT" -type f 2>/dev/null | wc -l)
  [ "$n" -ge "$EXPECTED" ] && break
  sleep 0.5
done
sleep 1

mygo-automation screenshot "$SHOT" | head -1

kill "$APP_PID" 2>/dev/null
sleep 0.5
kill -9 "$APP_PID" 2>/dev/null

echo
echo "输出目录文件数：$(find "$OUT" -type f | wc -l) / 期望 $EXPECTED"

bad=0
while IFS= read -r f; do
  rel="${f#"$PLAIN"/}"
  target="$OUT/$rel"
  if [ ! -f "$target" ]; then
    echo "  缺失：$rel"
    bad=$((bad + 1))
  elif ! cmp -s "$f" "$target"; then
    echo "  内容不一致：$rel"
    bad=$((bad + 1))
  fi
done < <(find "$PLAIN" -type f)

if [ "$bad" -eq 0 ]; then
  echo "端到端通过：所有文件逐字节一致"
  exit 0
fi
echo "端到端失败：$bad 个文件有问题"
exit 1
