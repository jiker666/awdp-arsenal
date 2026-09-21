# 03 · Pwn 防御一把梭

> pwn 的 AWDP 规则通常比 web 更严：常见"文件长度必须一致 / 改动 ≤N 字节"。
> 所以一切手法围绕**改指令不改长度**。

## 0. 打包格式（真实比赛）

```
修补包 = 改好的二进制 + update.sh，tar 一起交
update.sh:
  mv pwn_fixed /home/ctf/pwn      # 路径按题目说明
  chmod 755 /home/ctf/pwn
tar zcvf update.tar.gz update.sh pwn_fixed
```

最小改动规则生效时**禁止重新编译**（长度/结构对不上直接判违规），必须 patch 原文件。

## 1. patch 速查表（漏洞类型 → 手法）

来源：蚁景网安实验室《AWDPwn 漏洞加固总结》、Hello CTF《AWD 技巧》。

| 漏洞 | 手法 | 具体改动 |
|---|---|---|
| 整数溢出（负数绕过长度检查） | 符号跳转改无符号 | `jle`→`jbe`（0x7E→0x76）等，对照 §2 机器码表 |
| 栈溢出（read/scanf 读太长） | 把长度立即数改小 | `mov edx, 0x200`→`mov edx, 0x40`；x86 `push 0x200`(5字节)→`push 0x40; nop`(2+3 字节对齐) |
| 格式化字符串 | ① `printf(buf)` 调用改成 `puts(buf)`：把 `call printf@plt` 的目标地址换成 `puts@plt`（不换指令，只换 PLT 地址）② 或压参改 `mov edi, offset "%s"; mov esi, buf` | printf→puts 对多个 `\n` 的场景有行为差异（局限，见原文） |
| UAF（释放后未置零） | 劫持 `call free` 到自定义 stub：`free(ptr)` 后**把指针置零**再跳回 | stub 写在 .eh_frame（见 §4） |
| gets / scanf("%s") 无长度 | 整个换成自定义受限 read（syscall 白名单：只许读固定长度） | stub 写在 .eh_frame |
| if 判断范围错（改 price/age 那种逻辑洞） | 改跳转目标地址 | `js 0x40081C`→`js 0x400845` |
| 栈 canary 被泄露后绕过 | 反转校验跳转 | `jz`↔`jnz`（0x74↔0x75） |
| 后门函数（win/backdoor 调 system） | NOP 掉后门（见 §3） | — |

**How to patch（工具）**：
- IDA：Edit → Patch program → Assemble（写汇编自动编码）→ **Apply patches to input file**（⚠️ 必须点这步才真正写文件；Free 版没有该菜单）
- IDA + [Keypatch](https://github.com/keystone-engine/keypatch) 插件（推荐，汇编级 patch 神器）
- 命令行：[AwdPwnPatcher](https://github.com/aftern00n/AwdPwnPatcher)（交互式）、[evilPatcher](https://github.com/TTY-flag/evilPatcher)（见 §5）
- 纯脚本：`tools/pwn_patch.py`（nm 定位 + readelf 映射偏移 + 字节替换，本仓库实测流程）

**通用坑：vaddr ≠ 文件偏移**。IDA/objdump 显示的是虚拟地址，改文件要换算：
`偏移 = vaddr - PT_LOAD.vaddr + PT_LOAD.offset`（no-pie 程序通常就是 `vaddr - 0x400000`），`readelf -l` 可查。

## 2. 条件跳转机器码速查（打十六进制用的）

| 指令 | opcode | 指令 | opcode |
|---|---|---|---|
| jmp short | EB | jz/je | 74 |
| jnz/jne | 75 | js | 78 |
| jns | 79 | jg/jnle | 7F |
| jge/jnl | 7D | jl/jnge | 7C |
| jle/jng | 7E | jbe/jna | 76 |
| ja/jnbe | 77 | — | — |

改法：只换第一个 opcode 字节（短跳转 2 字节：opcode + rel8），长度不变。
套路：**有符号 ↔ 无符号**互换堵整数溢出（jle↔jbe / jl↔jb）；**零标志反转**堵 canary 泄露（74↔75）。

## 3. NOP 掉后门（栈溢出+后门类签到题的最快防御）

| 改法 | 字节 | 效果 |
|---|---|---|
| 后门函数入口首字节改 `0xC3`（ret） | 1 | 跳进来即返回，system 永远执行不到（推荐，改动最小）|
| `call system@plt` 改 5×`0x90` | 5 | 函数体照常走完，shell 调用没了，行为更温和 |

两者都保文件长度，hexdiff 友好。完整流程（含定位 strip 后门：`strings -tx | grep bin/sh` → IDA 交叉引用）见 `tools/pwn_patch.py`。

## 4. .eh_frame code cave：写"自定义函数"不换原文件结构

.eh_frame 段平时没有执行权限也用不到，可以：

1. 把自定义汇编 stub 写进 .eh_frame 空间
2. 把 LOAD 段 flags 改成 7（RWX）让它可执行
3. 把原程序 `call free` / `call printf` 的目标改到 stub

Hello CTF 实例：自定义 `read` 只允许读固定长度（堵 scanf %s）、自定义 `free+置零`（堵 UAF）、甚至整段 ptrace 父进程监控（见 §5）。改动集中、可控，是"最小改动规则下想多写点逻辑"的正解。

## 5. 通防 & 偏方（规则空白处才用）

| 招 | 做法 | 边界 |
|---|---|---|
| **NOP free** | `free@plt` 入口 1 字节 `0xC3` | 堵 UAF/double-free/tcache/fastbin/unsorted/consolidation 全家；**堵不住** House of Force、不经过 free 的直接溢出。Hello CTF 评价：有时候管用，不是啥时候都管用 |
| **dynsym 改名** | 把 dynsym 表里 `free` 的函数名字符串改成别的（如 `atoi`），链接器找不到 free → 调用变无害 | 依赖 ret2resolve 知识点；对静态链接无效 ⚠️ 未实测 |
| **alarm 时间差** ⭐ | `alarm(60)` 改 `alarm(3)`：checker 只跑 1~5 秒必过 SLA，而攻击者的 exploit（IO 暴力/多轮交互）需要 >5 秒 → 卡死 | Hello CTF 实战记录的阴招：checker 过了、exp 没法打完。**只骗 check，不防住漏洞** |
| **ptrace 沙箱** | eh_frame 写 fork+`PTRACE_TRACEME`+`PTRACE_SYSCALL` 的 stub，拦截 `execve/clone/fork`（加严可拦 `open/openat`），命中即 kill | VM 虚拟机平台可用；Docker 容器需 `CAP_SYS_PTRACE`（通常没有，给了也有逃逸风险）⚠️ 未实测 |

⚠️ 这些都是"对 checker 而不对漏洞"的偏方，官方大赛 hexdiff 检查一上就废。规则严 → 回 §1 老老实实按漏洞类型 patch。

## 6. 攻击侧最小包（web 选手视角）

只打"栈溢出 + 后门"签到题，一行都不多学：

```python
from pwn import *
p = remote('ip', port)
p.send(b'A'*偏移 + p64(后门地址))   # 偏移用 cyclic 定；后门用 nm/strings 找
p.sendline(b'cat /flag')
```

pwn 选手的世界（堆、IO、orw、syscall）不在本秘籍射程内。
