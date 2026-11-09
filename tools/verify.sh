#!/usr/bin/env bash
# 对拍脚本：用 rclone 生成加密样本，再用本项目的 Go 实现解密，
# 最后逐字节比对。修改加密逻辑后务必重跑。
#
# 依赖：rclone（通过 RCLONE 环境变量指定路径，默认取 PATH 里的 rclone）
set -u

RCLONE="${RCLONE:-rclone}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PLAIN="$WORK/plain"
PASSWORD="verify-password-2024"
SALT="verify-salt-2024"

pass=0
fail=0
failed_cases=""

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

winpath() { (cd "$1" && pwd -W 2>/dev/null || pwd); }

# 准备明文样本，覆盖各种边界
make_samples() {
  mkdir -p "$PLAIN/sub/deep"
  printf '' > "$PLAIN/empty.txt"
  printf 'A' > "$PLAIN/one.txt"
  printf 'hello alist crypt hello alist crypt' > "$PLAIN/small.txt"
  head -c 65536 /dev/urandom > "$PLAIN/exact-64k.bin"
  head -c 65537 /dev/urandom > "$PLAIN/over-64k.bin"
  head -c 1048576 /dev/urandom > "$PLAIN/one-mb.bin"
  printf '中文内容' > "$PLAIN/中文文件名.txt"
  printf 'deep' > "$PLAIN/sub/deep/嵌套文件.txt"
  printf 'spaces' > "$PLAIN/带 空格 的名字.txt"
}

# run_case <说明> <mode> <encoding> <dirEnc:true|false> <salt:yes|no>
CASE_N=0
run_case() {
  local label="$1" mode="$2" enc="$3" dirEnc="$4" useSalt="$5"

  # 每个用例用独立目录，避免 Windows 上删除不干净导致旧文件串进来
  CASE_N=$((CASE_N + 1))
  local caseDir="$WORK/case-$CASE_N"
  mkdir -p "$caseDir/enc"

  local passObscured saltLine=""
  passObscured=$("$RCLONE" obscure "$PASSWORD")
  if [ "$useSalt" = "yes" ]; then
    saltLine="password2 = $("$RCLONE" obscure "$SALT")"
  fi

  cat > "$caseDir/rclone.conf" <<EOF
[test]
type = crypt
remote = $(winpath "$caseDir/enc")
password = $passObscured
$saltLine
filename_encryption = $mode
directory_name_encryption = $dirEnc
filename_encoding = $enc
suffix = .bin
EOF

  if ! "$RCLONE" --config "$caseDir/rclone.conf" copy "$PLAIN/" test: --stats 0 >/dev/null 2>&1; then
    printf '  %-46s 跳过（rclone 加密失败）\n' "$label"
    return
  fi

  local saltArg=""
  [ "$useSalt" = "yes" ] && saltArg="$SALT"

  local outDir="$WORK/out-$CASE_N"
  mkdir -p "$outDir"
  local out
  out=$(cd "$ROOT" && go run ./cmd/crypt \
    -mode decrypt \
    -src "$(winpath "$caseDir/enc")" \
    -dst "$(winpath "$outDir")" \
    -password "$PASSWORD" \
    -salt "$saltArg" \
    -name-encryption "$mode" \
    -encoding "$enc" \
    -suffix ".bin" \
    -dir-encryption="$dirEnc" \
    -compare "$(winpath "$PLAIN")" 2>&1)

  if [ $? -eq 0 ]; then
    printf '  %-46s 通过\n' "$label"
    pass=$((pass + 1))
  else
    printf '  %-46s 失败\n' "$label"
    echo "$out" | sed 's/^/      /'
    fail=$((fail + 1))
    failed_cases="$failed_cases\n  - $label"
  fi
}

echo "生成测试样本…"
make_samples

echo "开始对拍："
run_case "standard / base32 / 目录加密 / 有盐"    standard  base32    true  yes
run_case "standard / base64 / 目录加密 / 有盐"    standard  base64    true  yes
run_case "standard / base32768 / 目录加密 / 有盐" standard  base32768 true  yes
run_case "standard / base32 / 目录不加密 / 有盐"  standard  base32    false yes
run_case "standard / base32 / 目录加密 / 默认盐"  standard  base32    true  no
run_case "off / base64 / 目录不加密 / 有盐"       off       base64    false yes
run_case "off / base32 / 目录不加密 / 有盐"       off       base32    false yes
run_case "obfuscate / base32 / 目录加密 / 有盐"   obfuscate base32    true  yes

echo
if [ "$fail" -eq 0 ]; then
  echo "全部通过：$pass 组配置"
  exit 0
fi
echo "通过 $pass 组，失败 $fail 组"
printf "失败用例：$failed_cases\n"
exit 1
