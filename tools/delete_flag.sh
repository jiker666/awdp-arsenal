#!/bin/sh
# ============================================================
# 05 删flag · rm 版（带一键撤回）
# ------------------------------------------------------------
# 和 01(chmod 000) 的区别：
#   rm    ：文件直接没了。防御侧不轮换的平台一删到底；
#           轮换型平台每回合重写会复活（那种平台用 01）
#   chmod ：文件还在，低权限读不了；裁判重写内容后权限仍保留
# 共同约束：规则明令禁改 flag 的赛不要交；被查到比丢分严重
# 不建议 chattr +i：轮换型平台写不进去，会把你判成服务异常
#
# 用法: sh 05_删flag.sh          删（自动备份到 /tmp/.oneshot_flag）
#       sh 05_删flag.sh undo     撤回（恢复内容+权限+属主）
# ============================================================
BAKDIR=/tmp/.oneshot_flag

case "${1:-}" in
undo)
    if [ -d "$BAKDIR" ] && [ -f "$BAKDIR/path" ]; then
        p=$(cat "$BAKDIR/path")
        cp "$BAKDIR/content" "$p"
        chmod "$(cat "$BAKDIR/perm")" "$p" 2>/dev/null
        chown "$(cat "$BAKDIR/owner")" "$p" 2>/dev/null
        rm -rf "$BAKDIR"
        echo "[oneshot] 已恢复 $p -> $(head -c 12 "$p")…"
    else
        echo "[oneshot] 没有备份（没删过或已撤回）"
    fi
    exit 0
    ;;
esac

rm -rf "$BAKDIR" && mkdir -p "$BAKDIR"
# 常见 flag 位置，第一个命中的删（要多点位自己往 for 列表里加）
for f in /flag /flag.txt /root/flag /home/*/flag; do
    [ -f "$f" ] || continue
    echo "$f"                    > "$BAKDIR/path"
    cp "$f"                      "$BAKDIR/content"
    stat -c '%a'    "$f"         > "$BAKDIR/perm"
    stat -c '%U:%G' "$f"         > "$BAKDIR/owner"
    if rm -f "$f" 2>/dev/null; then
        echo "[oneshot] deleted: $f   (撤回: sh $0 undo)"
        exit 0
    else
        rm -rf "$BAKDIR"
        echo "[oneshot] rm 失败：当前用户无权删 $f（真赛里平台以 root 跑 patch.sh，不会有这问题）"
        exit 1
    fi
done
echo "[oneshot] /flag /flag.txt 等常见位置都没找到，ls / 看一眼实际路径"
