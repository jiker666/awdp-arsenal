#!/bin/sh
# pwn-package.sh —— AWDP pwn 一键通防包生成器（输出真实比赛格式的 update.tar.gz）
#
# 三种模式:
#   sandbox  调 evilPatcher 打 seccomp 沙箱（默认挡 execve；预设可选加挡 open/openat 等）
#   nop      NOP 掉后门（走同目录 pwn_patch.py，栈溢出+后门类签到题专用）
#   chmod    纯 update.sh: chmod 000 /flag（判据试探 / 偷分，不需要二进制）
#
# 用法:
#   ./pwn-package.sh sandbox pwn01                     # 01_挡shell 预设
#   SBOX=02 ./pwn-package.sh sandbox pwn01             # 02_挡shell挡文件 预设
#   SBOX=/path/custom.asm ./pwn-package.sh sandbox pwn01
#   DEST=/home/ctf/pwn ./pwn-package.sh sandbox pwn01  # 指定二进制落盘路径(默认 /home/ctf/pwn)
#   ./pwn-package.sh nop pwn01
#   ./pwn-package.sh chmod
#
# 依赖:
#   sandbox 模式: python3 + pwntools + seccomp-tools；evilPatcher 本体先跑
#                ./get_evilpatcher.sh 拉到本目录（或 export EVILPATCHER=/path/evilPatcher.py）
#   nop     模式: python3 + binutils(nm/readelf/objdump)，Linux 下跑
#
# ⚠️ 交包铁律: 上传前人工核对 update.sh 里的 DEST 路径与题目说明一致；
#             sandbox 模式务必本地先跑一遍服务的正常功能（SLA 误杀 = 判负）。

set -e
MODE="${1:-}"; BIN="${2:-}"
DEST="${DEST:-/home/ctf/pwn}"
HERE=$(cd "$(dirname "$0")" && pwd)
FIXED=""

die() { echo "[-] $*" >&2; exit 1; }
[ "$MODE" = "chmod" ] || [ -n "$BIN" ] || die "用法见脚本头部注释（mode + 二进制）"
[ -f "$BIN" ] || [ "$MODE" = "chmod" ] || die "找不到二进制: $BIN"

case "$MODE" in
sandbox)
    EP="${EVILPATCHER:-$HERE/evilPatcher/evilPatcher.py}"
    [ -f "$EP" ] || die "evilPatcher 不在 $EP。先跑 $HERE/get_evilpatcher.sh，或 export EVILPATCHER=..."
    python3 -c 'import pwn' 2>/dev/null || die "缺 pwntools: pip3 install pwntools"
    command -v seccomp-tools >/dev/null || die "缺 seccomp-tools: gem install seccomp-tools"
    [ -x "$BIN" ] || chmod +x "$BIN"

    SBOX="${SBOX:-01}"
    case "$SBOX" in
    */*.asm) ASM="$SBOX" ;;                                  # 自定义规则路径
    *)  ASM=$(echo "$HERE"/sandboxs/"${SBOX}"_*.asm) ;;      # 预设编号(01/02/03)
    esac
    [ -f "$ASM" ] || die "找不到沙箱规则: $SBOX（看 sandboxs/ 目录）"
    echo "[*] 沙箱规则: $ASM"

    # 直接用绝对路径调，产物 <bin>.patch 落在当前目录
    python3 "$EP" "$BIN" "$ASM"
    FIXED="$BIN.patch"
    [ -f "$FIXED" ] || die "evilPatcher 没产出 $FIXED"
    A=$(wc -c < "$BIN" | tr -d ' '); B=$(wc -c < "$FIXED" | tr -d ' ')
    [ "$B" -le $((A + 256)) ] || die "产物超长($B > $A+0x100)，最小改动规则危险"
    echo "[+] 沙箱补丁: $FIXED (${A}B -> ${B}B, Δ$((B-A)))"
    ;;
nop)
    [ -f "$HERE/pwn_patch.py" ] || die "缺 $HERE/pwn_patch.py"
    python3 "$HERE/pwn_patch.py" "$BIN" "$BIN.fixed" ret
    FIXED="$BIN.fixed"
    ;;
chmod)
    echo "[*] chmod 模式：只动 flag 权限，不动二进制"
    ;;
*) die "未知模式: $MODE (sandbox|nop|chmod)" ;;
esac

# ---- 生成发布目录（tar 内统一用 basename，update.sh 里也引用 basename）----
if [ "$MODE" = "chmod" ]; then
    BASE=chmod; DIST="dist_chmod"
else
    FIXNAME=$(basename "$FIXED"); BASE=$(basename "$BIN"); DIST="dist_${BASE}_${MODE}"
fi
rm -rf "$DIST"; mkdir -p "$DIST"

if [ "$MODE" = "chmod" ]; then
cat > "$DIST/update.sh" <<'EOF'
#!/bin/sh
# 判据试探/偷分包：服务进程(题目用户)将读不了 /flag
# ⚠️ 若 checker 判据不是"读到 flag"，或规则要求 flag 完整可读，此包会失败，换真修复
chmod 000 /flag 2>/dev/null || echo "[-] chmod 失败(权限/路径不对)" >&2
exit 0
EOF
else
cat > "$DIST/update.sh" <<EOF
#!/bin/sh
# 上传前核对：DEST 必须与题目说明的二进制路径一致！
DEST='$DEST'
cp '$FIXNAME' "\$DEST" || { echo "[-] 覆盖 \$DEST 失败" >&2; exit 1; }
chmod 755 "\$DEST"
echo "[+] patched -> \$DEST"
EOF
cp "$FIXED" "$DIST/"
fi

sh -n "$DIST/update.sh"   # 语法自检，炸了就别交
( cd "$DIST" && tar zcf update.tar.gz update.sh ${FIXNAME:+"$FIXNAME"} )
echo "[+] 产出 $DIST/update.tar.gz:"; tar tzf "$DIST/update.tar.gz"
