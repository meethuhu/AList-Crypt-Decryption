#!/usr/bin/env bash
# 反向对拍：用本项目的实现加密，再用真实的 rclone 解密，
# 确认我们产出的密文 rclone 认。
#
# 正向对拍（rclone 加密 → 我们解密）见 tools/verify.sh。
set -u

RCLONE="${RCLONE:-rclone}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PLAIN="$WORK/plain"
PASSWORD="enc-verify-pass"
SALT="enc-verify-salt"

pass=0
fail=0

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

winpath() { (cd "$1" && pwd -W 2>/dev/null || pwd); }

make_samples() {
  mkdir -p "$PLAIN/nested"
  printf '' > "$PLAIN/empty.txt"
  printf 'A' > "$PLAIN/one.txt"
  printf 'plain text sample' > "$PLAIN/说明.txt"
  head -c 65536 /dev/urandom > "$PLAIN/exact-64k.bin"
  head -c 65537 /dev/urandom > "$PLAIN/over-64k.bin"
  head -c 200000 /dev/urandom > "$PLAIN/nested/photo.jpg"
  printf 'deep' > "$PLAIN/nested/深层文件.txt"
}

# run_case <说明> <mode> <encoding> <dirEnc>
run_case() {
  local label="$1" mode="$2" enc="$3" dirEnc="$4"

  local dir="$WORK/$(echo "$label" | tr -d ' /')"
  mkdir -p "$dir/our-enc" "$dir/rclone-dec"

  local common=(-password "$PASSWORD" -salt "$SALT" -name-encryption "$mode" \
                -encoding "$enc" -suffix .bin -dir-encryption="$dirEnc")

  if ! (cd "$ROOT" && go run ./cmd/crypt -mode encrypt \
        -src "$(winpath "$PLAIN")" -dst "$(winpath "$dir/our-enc")" \
        "${common[@]}" -quiet) >/dev/null 2>&1; then
    printf '  %-40s 失败（加密出错）\n' "$label"
    fail=$((fail + 1))
    return
  fi

  local obscured saltLine=""
  obscured=$("$RCLONE" obscure "$PASSWORD")
  saltLine="password2 = $("$RCLONE" obscure "$SALT")"

  cat > "$dir/rclone.conf" <<EOF
[encrypted]
type = crypt
remote = $(winpath "$dir/our-enc")
password = $obscured
$saltLine
filename_encryption = $mode
directory_name_encryption = $dirEnc
filename_encoding = $enc
suffix = .bin
EOF

  if ! "$RCLONE" --config "$dir/rclone.conf" copy encrypted: "$(winpath "$dir/rclone-dec")" \
       --stats 0 >/dev/null 2>&1; then
    printf '  %-40s 失败（rclone 解不开）\n' "$label"
    fail=$((fail + 1))
    return
  fi

  local bad=0
  while IFS= read -r f; do
    rel="${f#"$PLAIN"/}"
    if [ ! -f "$dir/rclone-dec/$rel" ] || ! cmp -s "$f" "$dir/rclone-dec/$rel"; then
      bad=$((bad + 1))
    fi
  done < <(find "$PLAIN" -type f)

  if [ "$bad" -eq 0 ]; then
    printf '  %-40s 通过\n' "$label"
    pass=$((pass + 1))
  else
    printf '  %-40s 失败（%d 个文件不一致）\n' "$label" "$bad"
    fail=$((fail + 1))
  fi
}

echo "生成明文样本…"
make_samples

echo "本项目加密 → rclone 解密："
run_case "standard/base64/目录加密"   standard  base64 true
run_case "standard/base32/目录加密"   standard  base32 true
run_case "standard/base64/目录不加密" standard  base64 false
run_case "off/base64/目录不加密"      off       base64 false
run_case "obfuscate/base32/目录加密"  obfuscate base32 true

echo
if [ "$fail" -eq 0 ]; then
  echo "全部通过：$pass 组配置，rclone 能正确解开我们加密的所有文件"
  exit 0
fi
echo "通过 $pass 组，失败 $fail 组"
exit 1
