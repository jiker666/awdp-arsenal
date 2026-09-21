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
| `sniper.py` | 攻击侧自动化踩点+参数电池+自动拿flag（纯标准库单文件） | python3 sniper.py http://host/ | 只读探测 |

⚠️ 使用顺序：交任何通防前，**手动过一遍功能页面**（误杀 SLA = 判负）。
每题判据不同，通防黑名单要对着 checker 的 payload 调，不要盲交。

pwn_patch.py 只覆盖"栈溢出+后门"这一类题；通用 patch（整数溢出/格式化串/UAF 等）
见 `../03_pwn防御/README.md` 速查表，建议配合 IDA Keypatch 使用。
