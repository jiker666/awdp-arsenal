# 02 · Web 防御一把梭

## 0. 决策表

| 条件 | 首选 | 次选 |
|---|---|---|
| 规则有最小改动/hexdiff 检查 | 真修复 | — |
| 判据 = checker 读到 flag | chmod 000 /flag | rm -f /flag（轮换型平台会复活，chmod 的权限位能活过轮换）|
| 判据 = 执行证据 / payload 回显 | 通防（黑名单对着判据调） | 真修复 |
| 代码能看懂 | **真修复的最短路径**（见 §2） | 通防 |
| 完全没头绪 | 先交 chmod 探判据 | 通防兜底 |

⚠️ 通防/删 flag 是规则空白处的偷分手段，官方大赛明确禁止（见 01 手册）。**先用最低成本探明判据，再决定投入**。

## 1. 最快 fix 的一个通用模式：在漏洞 sink 前加闸

比赛代码 90% 是"某个入口把用户输入直接喂给危险函数"。最快的修复**不是重写**，而是**在调用前加一层白名单/黑名单判断**（5ime 实录：Node 题在 `vm.run()` 前加关键词过滤、Python 题在 `waf()` 前加判断，都是几行的事）：

```js
// Node: vm.run 之前
const BLACK = ['__proto__', 'constructor', 'prototype', 'child_process', 'process.'];
if (BLACK.some(k => input.includes(k))) return res.status(403).end('hacker');
vm.run(input);
```

```python
# Python: render_template_string 之前
if any(k in name for k in ('{{', 'lipsum', 'cycler', '__globals__', '__subclasses__')):
    return abort(403)
return render_template_string(TPL, name=name)
```

配合规则判据（checker 用固定 payload 打你）——黑名单对着 payload 关键词写即可，不需要完备。

## 2. 按漏洞类型的修复速查

| 漏洞 | PHP | Python | Node/JS |
|---|---|---|---|
| SQL 注入 | PDO 预编译 `prepare`+`execute` | `cursor.execute(sql, (a,))` | `db.query('...?', [a])` |
| XSS | `htmlspecialchars($s, ENT_QUOTES)` | 模板自动转义（Jinja 默认开） | `escape-html`/模板转义 |
| LFI/路径穿越 | `basename()` + 白名单目录 `realpath` 前缀校验 | `os.path.realpath` 前缀校验 | `path.resolve` 前缀校验 |
| 命令注入 | `escapeshellarg($x)`；能不用 shell 就不用 | `subprocess.run([...], shell=False)` | `execFile(cmd, [args])` |
| 文件上传 | 白名单扩展名 + `getimagesize` 校验 + 随机文件名 | 同左 | `multer` 白名单 |
| SSTI | — | 模板和渲染**分离**：`render_template_string(TEMPLATE, name=user_input)`，模板字符串里不放用户输入 | EJS：不把用户输入拼进渲染选项 |
| 反序列化 | 避免 `unserialize`；必须用则 `allowed_classes` | 避免 `pickle.loads`；`yaml.safe_load` 替代 | 原型污染：deepMerge 里过滤 `__proto__/constructor/prototype`（三个都要挡，只挡 `__proto__` 会被 `constructor.prototype` 绕过） |
| XXE | `libxml_disable_entity_loader(true)` | `defusedxml` | — |

**原则**：最小 diff、保功能、别重构。 checker 同时会打功能检查（SLA），修太狠误杀自己。

## 3. patch.sh / update.sh 真实模板（按语言）

### 3.1 PHP（Apache，heredoc 直接覆盖源码）

```sh
#!/bin/sh
cp ping.php /var/www/html/ping.php      # 或 cat > ... <<'EOF' 全文写入
chown www-data:www-data /var/www/html/ping.php
apachectl -k graceful || true           # 平滑重载；失败别让脚本挂掉
```

注意：`<<'EOF'` 必须带引号，否则 `$` 会被 shell 展开。

### 3.2 Python / Flask（5ime 实录：cp + 杀进程 + 拉起）

```sh
#!/bin/sh
cp app.py /app/app.py
ps -ef | grep app.py | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
cd /app && nohup python3 app.py > /dev/null 2>&1 &
```

⚠️ 实测坑：Flask 如果开了 `--reload`（reloader 是父进程），**别 kill 子进程**——父进程会跟着退 → 容器重启 → 被判"补丁搞崩服务"。热重载场景直接 `touch 入口文件` 就够了。
⚠️ 杀进程方案要求脚本里必须把服务拉回来（`nohup ... &`），否则 SLA 直接挂。

### 3.3 Node / Express（同上模式）

```sh
#!/bin/sh
cp app.js /app/app.js
ps -ef | grep node | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
cd /app && nohup node app.js > /dev/null 2>&1 &
```

### 3.4 Java（war/jar 题）

- 最优：**只换单个 jar/依赖**（如 fastjson 题换成无漏洞版本同名 jar，wso2 题换官方修复 jar）——diff 小、无重构
- war 题：本地备好 Maven/Gradle 环境 + 各版本依赖，重新打包（这就是为什么赛前要备环境；Go/Java 不熟是多数队的失分点）
- 兜底：加一个全局 Filter 做 RASP（`SecFilter`，见 [java_filter 模板](https://github.com/XDSEC/JavaSecFilters)）⚠️ 未实测

### 3.5 打包提交格式

```sh
# 平台要 update.tar.gz 时（真实比赛主流格式）：
tar zcvf update.tar.gz update.sh ping.php    # update.sh + 所有修复文件
# 平台要单个 patch.sh 时：把文件用 heredoc 内联进脚本
```

pwn 的格式见 03_pwn防御/README。

## 4. 通防（规则空白时用）

三语言即用版在 `tools/`：`waf-php.sh` / `waf-python.sh` / `waf-node.sh`（均已在本仓库自训靶场 E2E 实测）。原理一句话：

| 语言 | 挂载点 | 特点 |
|---|---|---|
| PHP | `auto_prepend_file`（conf.d ini + graceful） | 不碰源码；对 GET/POST/COOKIE 统一过滤 |
| Python | `sitecustomize.py` hook `__import__`，包装 `Flask.wsgi_app` | 全局生效，比装饰器省事；先 `unquote_plus` 再检查 |
| Node | Express 中间件注入（幂等标记 `__oneshot__`） | 锚点插在 `express.urlencoded` / `=express()` 后 |
| Java | Filter / RASP | ⚠️ 模板多但都没法离线验证 |

第三方整活（赛前 clone 备好）：[awd-watchbird](https://github.com/le31ei/watchbird)、[CTF-WAF](https://github.com/an1sec/CTF-WAF)、[AoiAWD](https://github.com/DawnFlame/AoiAWD)、[k4l0ng_WAF](https://github.com/k4l0n9/k4l0ng_WAF)。

**通防调参心法**：黑名单别求完备，**对着 checker 判据写**。判据是读 flag → 挡 `flag` 字样；判据是回显 → 挡 marker 特征。宁可漏放，不可误杀（误杀 SLA = 判负）。

## 5. 动 flag（1 分钟偷分）

```sh
chmod 000 /flag          # 优于 rm：轮换型平台 rotate 会重写文件（rm 会复活），权限位能活过轮换
rm -f /flag              # 判据是"文件内容"型时用；带备份的完整脚本见 tools/delete_flag.sh
```

前提：①判据确实是读 flag；②规则不查 flag 完整性；③你是 root。低权限会失败，脚本要能报告出来。
风险：如果 checker 的 exploit 是"读 flag 失败时中途死掉且不自清理"，残留状态可能反噬 SLA（真实案例：删 flag → 探针 execSync 抛异常 → 污染残留 → 后续渲染 500）。

## 6. 不死马克制（AWD 遗产，AWDP 基本用不上但备着）

```sh
# 方法一：条件竞争循环删
find /var/www/html -name '*.php' -mmin -5 -delete
# 方法二：inotify 监听删除（耗资源）
# 方法三：禁用函数 php.ini: disable_functions = ...
# 方法四：Apache .htaccess 对特定文件 403
<Files "shell.php"> Require all denied </Files>
```

## 7. 实测踩坑集（自训靶场 E2E 结论）

1. **通防的副作用不进平台回滚范围**：ini 文件、sitecustomize.py、注入的代码、flag 权限——回滚只还原源码文件。交完通防要记录怎么手动拆（tools/ 各脚本头部写了撤销方法）。
2. **Flask 换子进程用 touch**：kill reloader 子进程 → 父进程跟退 → 容器重启 → 被判崩。见 §3.2。
3. **修 Node 原型污染必须三键全挡**：`__proto__` / `constructor` / `prototype`。只挡 `__proto__`，payload 换 `{"constructor":{"prototype":{...}}}` 照样污染。
4. **交包前过 SLA 的自测路径**：功能页手动点两遍 + 用 checker 的视角重放一遍功能请求。补丁把服务搞崩，很多平台单独有检测（容器重启时间戳变化）。
5. **修补脚本幂等**：`cp` 前判断存在、`|| true` 兜底。checker 多回合重跑不炸。
