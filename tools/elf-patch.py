#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elf-patch.py —— AWDP pwn 通用字节 patch 器（03_pwn防御 速查表的命令行落地）

把"jle→jbe / 改跳转目标 / NOP 后门"这类手工改字节做成一条命令，纯 Python 解析
ELF 头（不依赖 readelf/nm），改动量实时统计（hexdiff 预算提示）。

用法:
  # vaddr 定位 + 期望字节校验（防止改错地方）+ 换字节
  python3 elf-patch.py pwn01 --vaddr 0x40124a --expect 0f8e --hex 0f86
  # 直接给文件偏移
  python3 elf-patch.py pwn01 --off 0x124a --hex 76
  # 按原字节全文搜索定位（必须唯一命中），再替换
  python3 elf-patch.py pwn01 --find-hex "0f 8e" --hex "0f 86"
  # 快捷: NOP 掉 call（5字节）/ 入口 ret（1字节C3）/ 写字符串(自动补\0)
  python3 elf-patch.py pwn01 --vaddr 0x401193 --nop 5
  python3 elf-patch.py pwn01 --vaddr 0x401186 --ret
  python3 elf-patch.py pwn01 --off 0x3200 --str /bin/true
  # 输出默认 <名字>.patched；赛场拿不准工具好坏先跑: --selftest
"""
import argparse
import struct
import sys

PT_LOAD = 1


def load(data):
    if data[:4] != b'\x7fELF':
        sys.exit('[-] 不是 ELF 文件')
    bits = 4 if data[4] == 1 else 8 if data[4] == 2 else None
    if not bits:
        sys.exit('[-] 未知 ELF class: %d' % data[4])
    if bits == 8:
        phoff, = struct.unpack_from('<Q', data, 32)
        phentsize, phnum = struct.unpack_from('<HH', data, 54)
    else:
        phoff, = struct.unpack_from('<I', data, 28)
        phentsize, phnum = struct.unpack_from('<HH', data, 42)
    loads = []
    for i in range(phnum):
        ph = data[phoff + i * phentsize: phoff + (i + 1) * phentsize]
        p_type, = struct.unpack_from('<I', ph, 0)
        if p_type != PT_LOAD:
            continue
        if bits == 8:
            p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from('<QQQQ', ph, 8)
        else:
            p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from('<IIII', ph, 4)
        loads.append((p_vaddr, p_filesz, p_offset))
    return bits, loads


def vaddr_to_off(loads, vaddr):
    for va, sz, off in loads:
        if va <= vaddr < va + sz:
            return vaddr - va + off
    sys.exit('[-] vaddr 0x%x 不在任何 PT_LOAD 内' % vaddr)


def parse_hex(s):
    try:
        b = bytes.fromhex(s.replace(',', ' '))
    except ValueError:
        sys.exit('[-] hex 格式错: %r（如 "0f86" 或 "0f 86"）' % s)
    if not b:
        sys.exit('[-] 空 hex')
    return b


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--vaddr', type=lambda x: int(x, 0))
    ap.add_argument('--off', type=lambda x: int(x, 0))
    ap.add_argument('--find-hex', dest='find_hex')
    ap.add_argument('--expect', help='patch 前校验原字节（防改错地方），hex')
    ap.add_argument('--hex', help='写入的新字节，hex，如 "0f 86"')
    ap.add_argument('--nop', type=int, metavar='N', help='写 N 个 0x90')
    ap.add_argument('--ret', action='store_true', help='写 1 个 0xC3')
    ap.add_argument('--str', dest='raw_str', help='写字符串并补 \\x00')
    ap.add_argument('-o', '--out')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if not a.file:
        sys.exit(ap.format_help())
    data = bytearray(open(a.file, 'rb').read())
    bits, loads = load(data)

    # ① 定位
    if a.vaddr is not None:
        off = vaddr_to_off(loads, a.vaddr)
        print('[*] vaddr 0x%x -> 文件偏移 0x%x' % (a.vaddr, off))
    elif a.find_hex is not None:
        pat = parse_hex(a.find_hex)
        hits = [i for i in range(len(data) - len(pat) + 1) if data[i:i + len(pat)] == pat]
        if not hits:
            sys.exit('[-] 全文未找到 %s' % pat.hex())
        if len(hits) > 1:
            sys.exit('[-] 命中 %d 处(0x%s...)，加范围或换更长的特征' %
                     (len(hits), ' 0x'.join('%x' % h for h in hits[:5])))
        off = hits[0]
        print('[*] 唯一命中: 文件偏移 0x%x' % off)
    elif a.off is not None:
        off = a.off
    else:
        sys.exit('[-] 定位方式三选一: --vaddr / --off / --find-hex')

    # ② 新字节
    if a.hex:
        new = parse_hex(a.hex)
    elif a.nop:
        new = b'\x90' * a.nop
    elif a.ret:
        new = b'\xc3'
    elif a.raw_str is not None:
        new = a.raw_str.encode() + b'\x00'
    else:
        sys.exit('[-] 要写什么: --hex / --nop / --ret / --str')

    # ③ 校验 + 写
    old = bytes(data[off:off + len(new)])
    if a.expect:
        want = parse_hex(a.expect)
        if old[:len(want)] != want:
            sys.exit('[-] 原字节不符: 实际 %s 期望 %s（定位错了，别写！）' %
                     (old.hex(), want.hex()))
    data[off:off + len(new)] = new
    out = a.out or (a.file + '.patched')
    open(out, 'wb').write(data)

    orig = open(a.file, 'rb').read()
    diff = sum(1 for x, y in zip(orig, data) if x != y)
    print('[+] %s: 0x%x 处 %s -> %s（本次写 %d 字节；全文 hexdiff 共 %d 字节）' %
          (out, off, old.hex(), new.hex(), len(new), diff))


def selftest():
    """合成一个最小 ELF64（1 个 PT_LOAD），验证 vaddr 映射 / expect 校验 / patch / 差异统计"""
    e_ident = b'\x7fELF\x02\x01\x01' + b'\x00' * 9
    ehsize, phentsize, phnum = 64, 56, 1
    data_len = 0x100
    phoff = ehsize
    file_off = phoff + phentsize + 16        # 代码数据起始（对齐无所谓，测试用）
    vaddr = 0x400000 + file_off
    eh = e_ident + struct.pack('<HHIQQQIHHHHHH',
                               2, 0x3e, 1, 0, phoff, 0, 0,
                               ehsize, phentsize, phnum, 0, 0, 0)
    ph = struct.pack('<IIQQQQQQ', PT_LOAD, 5, file_off, 0x400000 + file_off, 0,
                     data_len, data_len, 0x1000)
    code = bytes.fromhex('0f8e10000000') + b'\x90' * (data_len - 6)
    # 布局: ELF头(64B) | Phdr(56B, 位于 phoff=64) | 16B 填充 | 代码
    blob = bytearray(eh + ph + b'\x00' * 16 + code)

    bits, loads = load(bytes(blob))
    assert (bits, len(loads)) == (8, 1), 'header 解析失败'
    off = vaddr_to_off(loads, vaddr)
    assert off == file_off, 'vaddr 映射错: %x' % off
    assert blob[off:off + 2] == bytes.fromhex('0f8e')
    blob[off:off + 2] = bytes.fromhex('0f86')          # jle -> jbe

    # find-hex 唯一性
    hits = [i for i in range(len(blob) - 1) if blob[i:i + 2] == bytes.fromhex('0f8e')]
    assert not hits, '替换后不应再有旧字节'
    hits2 = [i for i in range(len(blob) - 1) if blob[i:i + 2] == bytes.fromhex('0f86')]
    assert hits2 == [file_off], 'find-hex 唯一性失败'
    diff = sum(1 for x, y in zip(code, blob[file_off:]) if x != y)
    # 0f8e->0f86 首字节相同，真实 hexdiff = 1（这正是规则里"改动字节数"的口径）
    assert diff == 1, 'diff 统计错: %d' % diff
    print('[+] selftest PASS：ELF64 头解析 / vaddr→偏移 / 唯一搜索 / patch / hexdiff 计数 全部正确')


if __name__ == '__main__':
    main()
