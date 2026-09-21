#!/bin/sh
# make_package.sh —— web 防御包打包器：修复文件 → 双格式一次出
#   dist/update.tar.gz  平台收 tar 包用（update.sh + 修复文件）
#   dist/patch.sh       平台收单文件用（全部 heredoc 内联，100KB 限制内适用）
#   dist/manifest.txt   交付清单（交包前 30 秒复查用）
#
# 用法:
#   ./make_package.sh /var/www/html/ping.php=ping.php /app/app.py=app.py \
#       [--restart '命令'] [--cmd '命令']
#
#   dest=src：dest 是容器内绝对路径，src 是本地修复后的文件
#   --restart  附加"恢复服务"命令（强烈建议带上，现成片段见下）
#   --cmd      附加任意收尾命令（chmod/chown 之类）
#
# 现成的 --restart 片段（按语言挑）:
#   php:   --restart 'apachectl -k graceful || true'
#   flask: --restart 'touch /app/app.py'          # 热重载；reloader 场景禁止 kill 子进程
#   node:  --restart "ps -ef|grep node|grep -v grep|awk '{print \$2}'|xargs kill -9 2>/dev/null; cd /app && nohup node app.js >/dev/null 2>&1 &"
#
# 注意: src 路径带空格不支持；多个 src 同名会撞包（脚本会报错）。

set -e
cd "$(dirname "$0")/.."   # 仓库根目录，dist/ 落在根
DIST=dist
RESTART=""; CMD=""; PAIRS=""

while [ $# -gt 0 ]; do
    case "$1" in
    --restart)   RESTART="$2"; shift 2 ;;
    --cmd)       CMD="$2"; shift 2 ;;
    --restart=*) RESTART="${1#--restart=}"; shift ;;
    --cmd=*)     CMD="${1#--cmd=}"; shift ;;
    -*)          echo "[-] 未知选项: $1" >&2; exit 1 ;;
    *=*)         PAIRS="$PAIRS $1"; shift ;;
    *)           echo "[-] 参数要 dest=src 形式: $1" >&2; exit 1 ;;
    esac
done
[ -n "$PAIRS" ] || { sed -n '3,12p' "$0"; exit 1; }

rm -rf "$DIST"; mkdir -p "$DIST"
: > "$DIST/manifest.txt"

# ---- update.tar.gz ----
U="$DIST/update.sh"
printf '#!/bin/sh\n# 自动生成 by make_package.sh —— 交包前肉眼过一遍!\n' > "$U"
NAMES=""
for p in $PAIRS; do
    dest=${p%%=*}; src=${p#*=}; name=$(basename "$src")
    case "$dest" in /*) : ;; *) echo "[-] 目标路径要用绝对路径: $dest" >&2; exit 1 ;; esac
    [ -f "$src" ] || { echo "[-] 找不到本地文件: $src" >&2; exit 1; }
    echo "$NAMES" | tr ' ' '\n' | grep -qx "$name" && { echo "[-] 同名文件撞包: $name" >&2; exit 1; }
    NAMES="$NAMES $name"
    printf "cp '%s' '%s' || { echo '[-] cp %s 失败' >&2; exit 1; }\n" "$name" "$dest" "$dest" >> "$U"
    printf 'chown --reference="%s" "%s" 2>/dev/null || true\n' "$dest" "$dest" >> "$U"
    cp "$src" "$DIST/$name"
    printf '%s <= %s\n' "$dest" "$src" >> "$DIST/manifest.txt"
done
[ -n "$RESTART" ] && { printf '%s\n' "$RESTART" >> "$U"; printf 'restart: %s\n' "$RESTART" >> "$DIST/manifest.txt"; }
[ -n "$CMD" ]    && { printf '%s\n' "$CMD" >> "$U";       printf 'cmd: %s\n' "$CMD" >> "$DIST/manifest.txt"; }
printf 'exit 0\n' >> "$U"
sh -n "$U" || exit 1

# ---- patch.sh（单文件内联版）----
P="$DIST/patch.sh"
printf '#!/bin/sh\n# 自动生成 by make_package.sh（单文件提交版）—— 交包前肉眼过一遍!\n' > "$P"
MK="PKGEOF7c1a9"
for p in $PAIRS; do
    dest=${p%%=*}; src=${p#*=}
    while grep -qx "$MK" "$src" 2>/dev/null; do MK="${MK}x"; done   # 内容撞标记就换
    printf "cat > '%s' <<'%s'\n" "$dest" "$MK" >> "$P"
    cat "$src" >> "$P"
    printf '%s\n' "$MK" >> "$P"
done
[ -n "$RESTART" ] && printf '%s\n' "$RESTART" >> "$P"
[ -n "$CMD" ]    && printf '%s\n' "$CMD" >> "$P"
printf 'exit 0\n' >> "$P"
sh -n "$P" || exit 1

( cd "$DIST" && tar zcf update.tar.gz update.sh $NAMES )
echo "[+] 产出 $DIST/:"
sed 's/^/    /' "$DIST/manifest.txt"
echo "    update.tar.gz: $(tar tzf "$DIST/update.tar.gz" | tr '\n' ' ')"
echo "    patch.sh:      $(wc -c < "$DIST/patch.sh" | tr -d ' ') 字节"
