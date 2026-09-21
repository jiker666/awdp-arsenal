# sandboxs/ · seccomp 沙箱预设（配合 `../pwn-package.sh sandbox` 用）

规则 DSL 是 [evilPatcher](https://github.com/TTY-flag/evilPatcher)（内嵌 seccomp-tools）的语法，
`A = sys_number` 取调用号逐条判断，命中 `dead` 即杀进程，否则 `ALLOW`。
`A >= 0x40000000 ? dead` 是堵 x32 ABI 绕过的标准写法（amd64 下必带）。

**选哪个（先想清楚 SLA，杀错系统调用 = 服务死 = 判负）**：

| 预设 | 挡什么 | 剩什么攻击面 | SLA 风险 |
|---|---|---|---|
| `01_挡shell` | x32、execve、execveat | ROP 直接 orw（open/read/write）读 flag 不经过 shell | ⭐ 极低：服务自身几乎不会 execve |
| `02_挡shell_挡读文件` | 01 + open、openat、open_by_handle_at | 基本闷死：shell 和 orw 都没了 | ⭐⭐⭐ **服务自己读文件也会死**（启动读 flag 进堆、读配置、读题库的题别用） |
| `03_挡反弹` | socket/connect/bind/listen、clone、execve | 无网无 shell；本地 orw 仍可读 flag | ⭐⭐ **clone 一杀，fork 型服务（accept 循环自己 fork 的）当场全灭**；socat/xinetd 派生的不受影响 |

**决策顺序**：先 `01` 保命（挡住绝大多数 getshell 型 checker exploit）→ checker 还能出分再换 `02`。
`03` 只在"判据是反弹 shell/带外交互"时用。

自定义：抄一份 `.asm`，加一行 `A == 系统调用名 ? dead : next` 即可。
调用号名字以 `seccomp-tools asm` 支持的为准，更多样例看 evilPatcher 自带 `sandboxs/` 目录。
