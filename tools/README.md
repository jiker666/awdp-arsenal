# tools/ 即用脚本

除标注外，均在维护者自建 AWDP 靶场（PHP8.2/Apache、Flask3、Node20/Express/EJS 三题）
按真实平台流程 E2E 实测过：容器内以 root 执行 → SLA 功能检查 → 攻击探针 → 全绿。

| 脚本 | 用途 | 用法 | 撤销 |
|---|---|---|---|
| `waf-php.sh` | PHP 通防：auto_prepend_file 全局过滤，不碰源码 | bash waf-php.sh | 头部注释 |
| `waf-python.sh` | Python/Flask 通防：sitecustomize 包装 wsgi_app | bash waf-python.sh | 头部注释 |
| `waf-node.sh` | Node/Express 通防：中间件注入（幂等） | bash waf-node.sh | 头部注释 |
| `delete_flag.sh` | 删 flag / chmod 000，带备份与一键撤回 | bash delete_flag.sh [chmod\|rm] | bash delete_flag.sh undo |
| `pwn_patch.py` | NOP 掉后门：1 字节 ret 或 5 字节 NOP，长度不变 | python3 pwn_patch.py demo demo_fixed [ret\|nop] | — |
| `pwn-package.sh` | pwn 一键通防包：sandbox(evilPatcher)/nop/chmod 三模式 → update.tar.gz | ./pwn-package.sh sandbox pwn01 | — |
| `make_package.sh` | web 防御包打包器：修复文件 → update.tar.gz + 单文件 patch.sh 双格式 | ./make_package.sh /容器路径/file=本地file --restart '...' | — |
| `get_evilpatcher.sh` | 赛前有网时拉 evilPatcher 到本目录（断网赛场直接用） | ./get_evilpatcher.sh | rm -rf evilPatcher |
| `sniper.py` | 攻击侧自动化踩点+参数电池+自动拿flag（纯标准库单文件） | python3 sniper.py http://host/ | 只读探测 |
| `sandboxs/` | seccomp 沙箱预设（挡shell / 挡shell+挡读文件 / 挡反弹），风险表见其 README | SBOX=02 ./pwn-package.sh sandbox pwn01 | — |

**pwn 通防链路**（赛场机上跑，本仓库不内置 evilPatcher——原作者没挂 license，赛前自己拉）：

```
赛前: ./get_evilpatcher.sh && pip3 install pwntools && gem install seccomp-tools
赛场: ./pwn-package.sh sandbox 二进制名        # 默认 01_挡shell； checker 还能出分再 SBOX=02
      ./pwn-package.sh nop 二进制名            # 栈溢出+后门类签到题
      ./pwn-package.sh chmod                   # 判据试探 / 偷分
```

⚠️ 使用顺序：交任何通防前，**手动过一遍功能页面**（误杀 SLA = 判负）。
每题判据不同，通防黑名单要对着 checker 的 payload 调，不要盲交。

`pwn-package.sh`/`make_package.sh` 已过 shell 语法自检（sh -n），完整链路在赛场 Linux 机器上
首次使用时先拿一题练手。`pwn_patch.py` 只覆盖"栈溢出+后门"这一类题；通用 patch
（整数溢出/格式化串/UAF 等）见 `../03_pwn防御/README.md` 速查表，建议配合 IDA Keypatch 使用。
