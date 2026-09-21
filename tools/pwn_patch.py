#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# fix.py —— 防御侧：NOP 掉后门（最小改动，文件长度不变）
# 用法: python3 fix.py demo demo_fixed [ret|nop]
#   ret（默认，1 字节）：win() 入口第一个字节改成 0xC3（ret 指令）
#        → 跳进来立刻返回，system 永远执行不到
#   nop（5 字节）：win() 里 `call system@plt` 的 5 字节改成 90 90 90 90 90
#        → 函数还在，但 shell 调用被抹掉，之后正常走函数尾声返回
# 两种都保持文件长度一致（最小改动规则友好）。
import subprocess
import sys

SRC, DST = sys.argv[1], sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else 'ret'
data = bytearray(open(SRC, 'rb').read())


def vaddr_to_off(vaddr):
    """虚拟地址 → 文件偏移：读 program headers，找包含它的 PT_LOAD"""
    ph = subprocess.check_output(['readelf', '-lW', SRC]).decode()
    for line in ph.splitlines():
        parts = line.split()
        if 'LOAD' in parts[:1] + parts[1:2] and len(parts) >= 6:
            try:
                off, va = int(parts[1], 16), int(parts[2], 16)
                sz = int(parts[4], 16)
            except ValueError:
                continue
            if va <= vaddr < va + sz:
                return vaddr - va + off
    sys.exit('[-] vaddr 映射失败')


# ① 找 win
nm = subprocess.check_output(['nm', SRC]).decode()
win = None
for line in nm.splitlines():
    if line.rstrip().endswith(' win'):
        win = int(line.split()[0], 16)
        break
if win is None:
    sys.exit('[-] 没找到 win 符号')

if MODE == 'ret':
    off = vaddr_to_off(win)
    print('[*] win @ 0x%x, file offset 0x%x, 原字节 %s' %
          (win, off, data[off:off + 4].hex()))
    data[off] = 0xC3                       # 一字节 ret
else:
    # ② 找 win 里的 call system@plt
    dis = subprocess.check_output(
        ['objdump', '-d', '--start-address=%d' % win,
         '--stop-address=%d' % (win + 64), SRC]).decode()
    call_addr = None
    for line in dis.splitlines():
        if 'call' in line and 'system@plt' in line:
            call_addr = int(line.split(':')[0].strip(), 16)
            break
    if call_addr is None:
        sys.exit('[-] win 里没找到 call system@plt')
    off = vaddr_to_off(call_addr)
    print('[*] call system @ 0x%x, file offset 0x%x, 原字节 %s' %
          (call_addr, off, data[off:off + 5].hex()))
    data[off:off + 5] = b'\x90' * 5        # 五字节 NOP

open(DST, 'wb').write(data)
diff = sum(1 for a, b in zip(open(SRC, 'rb').read(), data) if a != b)
print('[+] 已生成 %s（改动 %d 字节，长度不变）' % (DST, diff))
