# 01 · 开赛手册：0-20 分钟 + 四小时时间线

## 开赛 0-5 分钟：读题面 + 读规则

- [ ] **逐字读规则**：最小改动？禁通防？二进制改动字节数上限？patch 还是 update.tar.gz？
  - 有 hexdiff/长度检查 → 歪招全废，直接进真修复路线
  - 真实案例：CISCN 17 届决赛 pwn 修补包 = 二进制 + `update.sh`（`mv pwn_fix /home/ctf/pwn && chmod 755`）；2025 CCB 半决赛规则明确"最小改动、不得通防、二进制 ≤5 字节 & 文件长度一致"
- [ ] **确认修补脚本文件名和执行方式**：有人把 `patch.sh` 交成 `pacth.sh` 白给一整场（5ime 实录）
- [ ] 看每题附件：`README`/`Dockerfile`/`docker-compose.yml` → 语言、框架、版本、入口

## 5-20 分钟：三线并发

```
队友A（攻击手）：跑自动化踩点器 + 手打签到题
队友B（防御手）：所有题先交一发「保底包」
队友C：开源题 diff / Java 题指纹
```

保底包顺序（详见 02_web防御/决策表）：

1. 拿不准判据 → `chmod 000 /flag` 探路（1 分钟，输了不亏）
2. 能看懂代码 → 直接真修复最短路径（见 02 的"最快 fix"）
3. 看不懂 → 上对应语言通防（tools/ 里有现成的）

## 四小时时间线（4 web + 4 pwn 版）

| 时段 | 攻击侧 | 防御侧 |
|---|---|---|
| 0:00-0:20 | 自动化踩点全量题 | 全题保底包交出去 |
| 0:20-1:00 | 签到题手打（别人也在打，拼速度） | 逐题换真修复 |
| 1:00-2:00 | 中档题（有 hint/Qwen 辅助分析数据流） | 真修复过不了的回退通防调参 |
| 2:00-3:00 | 组件脸题 15 分钟赌一把（五特征识洞，见 04） | 收尾：验证 SLA、确认分落袋 |
| 3:00-4:00 | 只留 1-2 人打"能出的"；其余复查防御 | 全题最后一轮功能自检 |

## 分档取舍（每题先定性再投入）

- **S 签到**（裸命令注入/裸 SSTI）：手打，目标 <10 分钟
- **A 中档**（有过滤的黑名单绕过/链式）：Qwen/队友辅助，30 分钟止损
- **B 组件脸**（Java/开源魔改）：只赌 15 分钟五特征；赌不中弃
- **C 硬题**：0 分钟攻击投入，防御走真修复/通防完事

## 断网工具箱打包清单（赛前准备）

- 各语言环境：PHP/Python/Node/Java/Golang 的 Docker 镜像提前 pull 好（赛场拉不动）
- 离线 pip/npm/pear 包：flask、jinja2、express、ejs、fastjson 各版本
- **pwn 通防链路**：`tools/get_evilpatcher.sh` 拉好 evilPatcher + `pip3 install pwntools` + `gem install seccomp-tools`（赛场机也要装这套）
- 反编译：jd-gui/jadx、IDEA（Java）；IDA/Ghidra + keypatch 插件（pwn）
- 脚本库：本仓库 tools/ 全部 + 第三方 WAF（awd-watchbird / CTF-WAF / AoiAWD）
- payload 文档：本仓库 04_攻击套路 + fastjson/shiro/log4j 各版本本地 payload 库
- 一个能跑大模型的笔记本（如果规则允许）
