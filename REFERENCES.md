# REFERENCES · 参考来源

本秘籍大部分招数收集自各队公开分享的 writeup / 博客 / 开源仓库，
向原作者致谢（排名不分先后）。标注 ⚠️ 的手法未在本地靶场实测，来自原文记录。

## 赛制与策略

- [第十七届 CISCN 总决赛 AWDP PWN 部分题解 · 看雪学苑](https://www.kanxue.com) — 修补包格式（mv+chmod）、决赛 pwn 攻防实战
- [CTF-Archives/2025-CCB-CISCN-Semis · GitHub](https://github.com/CTF-Archives/2025-CCB-CISCN-Semis) — 2025 半决赛规则：最小改动、禁通防、二进制 ≤5 字节且长度一致、web 改单 jar
- [AWD中二进制补丁的常见手工打法 · 长亭科技](https://rivers.chaitin.cn) — checker 会 hexdiff ≤100 字节反通防；寄存器约束下的指令替换
- [CTF线下赛AWDP总结 · 5ime](https://5ime.cn/awdp.html) — "通防住就是赚到"；多语言环境准备；真实 patch.sh（cp+kill+nohup）模板；pacth.sh 拼写翻车实录
- [速成AWDP · secevery](https://www.secevery.com) — 赛前备 WAF、修比打更稳
- [AWDP 赛制详解&应对方法 · CSDN](https://blog.csdn.net) — .htaccess 403 防固定文件、update.sh 需可重置进程

## Web 防御

- [CTF AWD/AWDP Web方向 Fix Patch 学习文档 · CN-SEC（原作者 Zacarx 随笔）](https://cn-sec.com/archives/3888530.html) — 按漏洞×语言的修复模板全集、WAF、文件监控
- [AWDP总结（Web） · CSDN](https://blog.csdn.net) — 前置关键词过滤的最快 fix 模式
- WAF 开源仓库：[awd-watchbird](https://github.com/le31ei/watchbird) / [CTF-WAF](https://github.com/an1sec/CTF-WAF) / [AoiAWD](https://github.com/DawnFlame/AoiAWD) / [k4l0ng_WAF](https://github.com/k4l0n9/k4l0ng_WAF)

## Pwn 防御

- [AWDPwn 漏洞加固总结 · 蚁景网安实验室](https://www.yijinglab.com/specialized/20210802105603) — 整数溢出 jle→jbe、栈溢出改 read 长度、printf→puts、UAF 劫持 free+置零、if 范围改跳转、gets→read 替换
- [【PWN】AWD 技巧 · Hello CTF](https://hello-ctf.com/hc-awd/awd_pwn.exp) — keypatch 用法、条件跳转机器码表、.eh_frame code cave（改 LOAD flags=7）、dynsym 函数名改 free→atoi ⚠️、alarm(60)→alarm(3) 时间差骗 checker ⭐、ptrace 拦 syscall 型通防 ⚠️、[evilPatcher](https://github.com/TTY-flag/evilPatcher)
- [AwdPwnPatcher · aftern00n](https://github.com/aftern00n/AwdPwnPatcher) — 交互式 pwn patch 工具
- [Keypatch · keystone-engine](https://github.com/keystone-engine/keypatch) — IDA 汇编级 patch 插件

## 其它

- [fushuling 的 AWDP 系列 · 博客园](https://www.cnblogs.com/fushuling) — update.tar.gz 提交流程与判罚分析
- [AWD-Guide · AabyssZG](https://github.com/AabyssZG/AWD-Guide) — AWD（前代赛制）全家桶：不死马、WAF、流量
- JavaSecFilters / 各大 fastjson-shiro-log4j 本地 payload 库 — 见各官方仓库

## 本仓库自测部分

维护者自建 AWDP 训练靶场（三题：PHP 命令注入 / Flask SSTI / Node 原型污染+EJS RCE，
含 SLA+多步探针的本地 check 平台）E2E 实测的结论：
通防副作用不在回滚范围、Flask reloader 不能 kill 子进程、原型污染必须三键全挡、
RCE payload 无条件自清理、chmod 000 优于 rm（轮换型平台）、dash 重定向不展开 glob 等。
