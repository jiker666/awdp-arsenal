#!/bin/sh
# get_evilpatcher.sh —— 赛前（有网时）跑一次，把 evilPatcher 拉到本目录，断网赛场直接用
# 赛场机器上还要装两个依赖（写进 U 盘里的赛前清单）:
#   pip3 install pwntools
#   gem install seccomp-tools
cd "$(dirname "$0")" || exit 1
command -v git >/dev/null || { echo "[-] 缺 git"; exit 1; }
rm -rf evilPatcher
git clone --depth 1 https://github.com/TTY-flag/evilPatcher.git || exit 1
[ -f evilPatcher/evilPatcher.py ] && echo "[+] 已就位: tools/evilPatcher/evilPatcher.py"
python3 -c 'import pwn' 2>/dev/null && echo "[+] pwntools OK" || echo "[!] 缺 pwntools: pip3 install pwntools"
command -v seccomp-tools >/dev/null && echo "[+] seccomp-tools OK" || echo "[!] 缺 seccomp-tools: gem install seccomp-tools"
