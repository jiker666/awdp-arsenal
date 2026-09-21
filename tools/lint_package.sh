#!/bin/sh
# lint_package.sh —— 防御包交包前 30 秒自检（web 的 update.tar.gz / patch.sh / pwn 包通用）
#
# 用法: ./lint_package.sh <update.tar.gz 或 patch.sh 或 update.sh>
#
# 检查项:
#   1. tar 结构：顶层必须有 update.sh
#   2. 所有 .sh 过 sh -n 语法检查
#   3. 危险命令黑名单（平台大概率直接拒收或判负）
#   4. update.sh 里引用的源文件是否都在包里（cp/mv 的第一个参数）
#   5. 打印"交包前人工清单"（工具查不了的靠眼睛）

set -u
F="${1:-}"
[ -n "$F" ] || { sed -n '2,9p' "$0"; exit 1; }
[ -f "$F" ] || { echo "[-] 找不到: $F"; exit 1; }

TMP=$(mktemp -d)
FAIL=0
bad() { echo "[✗] $*"; FAIL=1; }
ok()  { echo "[✓] $*"; }

# ---- 解包/落位 ----
case "$F" in
*.tar.gz|*.tgz)
    tar xzf "$F" -C "$TMP" 2>/dev/null || { echo "[-] tar 解不开"; exit 1; }
    [ -f "$TMP/update.sh" ] && ok "tar 顶层有 update.sh" || bad "tar 顶层没有 update.sh（平台认这个入口）"
    SHLIST=$(find "$TMP" -name '*.sh')
    ;;
*.sh) cp "$F" "$TMP/update.sh"; SHLIST="$TMP/update.sh" ;;
*) echo "[-] 只认 .tar.gz / .sh"; exit 1 ;;
esac

# ---- 语法 ----
for s in $SHLIST; do
    sh -n "$s" 2>/dev/null && ok "sh -n $(basename "$s")" || bad "$(basename "$s") 语法错误"
done

# ---- 危险命令 ----
PAT='rm -rf /|mkfs|dd if=|shutdown|reboot|halt|poweroff|:(){'
for s in $SHLIST; do
    if grep -Eq "$PAT" "$s"; then
        bad "$(basename "$s") 含危险命令: $(grep -En "$PAT" "$s" | head -3 | cut -c1-80 | tr '\n' ' ')"
    else
        ok "$(basename "$s") 无危险命令"
    fi
done

# ---- tar 里引用的文件齐不齐 ----
if echo "$F" | grep -q 'tar'; then
    for src in $(grep -E "^[[:space:]]*(cp|mv|install)[[:space:]]" "$TMP/update.sh" \
                 | awk '{print $2}' | tr -d "'\""); do
        case "$src" in /*|"") continue ;; esac       # 绝对路径/空不管（拷系统文件之类）
        [ -f "$TMP/$src" ] || bad "update.sh 引用了 ${src}，但包里没有"
    done
    ok "引用文件检查完（若上方有 ✗ 就是缺文件）"
fi

rm -rf "$TMP"
echo
echo "═══ 交包前人工清单（眼睛过，工具替不了）═══"
echo "  1. update.sh 里的目标路径 = 题目说明的路径？（一字不差）"
echo "  2. 修补后的功能本地点过两遍？（SLA 误杀=判负）"
echo "  3. 脚本幂等？再跑一遍不炸？"
echo "  4. 失败路径有兜底（|| true / 错误提示），不会把服务搞挂？"
echo "  5. 文件名/格式 = 平台要求（patch.sh vs update.tar.gz，别打成 pacth.sh）"
[ "$FAIL" = 0 ] && echo "═══ 自动检查全绿，可以交 ═══" || { echo "═══ 有 ✗，修完再交 ═══"; exit 1; }
