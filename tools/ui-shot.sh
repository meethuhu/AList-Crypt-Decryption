#!/usr/bin/env bash
# 开发辅助：编译 e2e 版本、启动、截图，用来肉眼检查界面。
# 用法：tools/ui-shot.sh <输出png> [demo]
#   第二个参数为 demo 时，会填入一组测试数据再截一张。
set -u

export PATH="$PATH:$(go env GOPATH)/bin"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOCK="C:/Users/withu/AppData/Local/Temp/alist.sock"
OUT="${1:-C:/Users/withu/AppData/Local/Temp/alist-shot.png}"
DEMO="${2:-}"

ENC="C:/Users/withu/AppData/Local/Temp/crypt64/enc"
DST="C:/Users/withu/AppData/Local/Temp/crypt64/out"
PW="test-password-123"
SALT="test-salt-456"

cd "$ROOT" || exit 1

mygo-automation close >/dev/null 2>&1

go build -tags e2e -o /tmp/alistcrypt-e2e.exe . || exit 1

MYGO_AUTOMATION="$SOCK" /tmp/alistcrypt-e2e.exe >/tmp/alist-app.log 2>&1 &
APP_PID=$!
sleep 3

mygo-automation open --socket "$SOCK" >/dev/null || { echo "无法连接应用"; kill "$APP_PID" 2>/dev/null; exit 1; }

if [ "$DEMO" = "demo" ]; then
  mygo-automation fill key=src "$ENC" >/dev/null
  mygo-automation fill key=dst "$DST" >/dev/null
  mygo-automation fill key=pw "$PW" >/dev/null
  mygo-automation fill key=salt "$SALT" >/dev/null

  # 折叠面板不支持 Key，只能从最新快照里按角色和文本找
  ADV=$(mygo-automation snapshot -i | grep 'disclosure.*高级选项' | head -1 | awk '{print $1}')
  [ -n "$ADV" ] && mygo-automation press "$ADV" >/dev/null
  sleep 1.5
fi

mygo-automation screenshot "$OUT" | head -1

kill "$APP_PID" 2>/dev/null
sleep 0.5
kill -9 "$APP_PID" 2>/dev/null
exit 0
