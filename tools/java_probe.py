#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""java_probe.py —— Java 题五特征探测（04_攻击套路 §5 的工具化）

对着一个 URL 打一轮只读探测，按特征报"像什么、下一步干什么"。
不做任何攻击动作（无 payload 发送、无 DNS/log 外带），识别得出就转本地 payload 库手打，
15 分钟赌不中就撤——这是 B 档题的全部投入。

用法: python3 java_probe.py http://1.2.3.4:8080/
"""
import re
import sys
import urllib.error
import urllib.request

UA = {'User-Agent': 'Mozilla/5.0 (probe)'}


def get(url, timeout=6):
    """返回 (status, headers, body前4KB) ；异常也返回状态便于判存活"""
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(4096).decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(4096).decode('utf-8', 'replace') if e.fp else ''
    except Exception as e:
        return -1, {}, str(e)[:120]


def probe(base):
    base = base.rstrip('/')
    hits = []          # (命中特征, 下一步)

    st, hd, body = get(base + '/')
    if st == -1:
        sys.exit('[-] 连不上 %s（%s）' % (base, body))
    hd_low = {k.lower(): v for k, v in hd.items()}
    cookies = hd_low.get('set-cookie', '')

    print('[*] GET / -> %d' % st)

    # ① Shiro：rememberMe 探测（官方删除标记是铁证）
    req = urllib.request.Request(base + '/', headers={**UA, 'Cookie': 'rememberMe=1'})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            sc = dict(r.headers).get('Set-Cookie', '')
    except urllib.error.HTTPError as e:
        sc = dict(e.headers or {}).get('Set-Cookie', '')
    except Exception:
        sc = ''
    if 'rememberMe=deleteMe' in sc:
        hits.append(('Shiro 反序列化', 'rememberMe=deleteMe 响应铁证；本地库翻 shiro 版本链（≤1.2.24 全通杀）'))

    # ② Spring actuator（200 + JSON 就有戏）
    for p in ('/actuator', '/actuator/env', '/actuator/heapdump'):
        s, _, b = get(base + p)
        if s == 200 and (b.lstrip().startswith('{') or '"_links"' in b):
            hits.append(('Spring Boot actuator: ' + p,
                         'env 泄露配置/密钥，heapdump 里 grep 密码；有 jolokia 可打 RCE'))

    # ③ 反序列化魔数回显点 / fastjson 报错页
    s, _, b = get(base + '/')
    if re.search(r'fastjson|jackson|JSONProvider', b, re.I):
        hits.append(('fastjson/jackson 痕迹', '找 JSON 接口发 {"@type":...}，版本≤1.2.47 老链直接打'))

    # ④ Whitelabel（Spring 错误页，说明有可控错误页/SpEL 路线）
    if 'Whitelabel' in body or 'whitelabel' in body.lower():
        hits.append(('Spring Whitelabel', 'SpEL 注入老题；或 /actuator 姊妹路线'))

    # ⑤ JSESSIONID = 纯 Java 栈确认（不一定有洞，给方向）
    if 'jsessionid' in cookies.lower():
        hits.append(('Java 栈确认 (JSESSIONID)', '栈是 Java：翻 cookie/参数找 rO0AB 或 rememberMe'))

    # ⑥ Druid / Tomcat manager（泄露型入口；看内容不光看状态码，防 SPA catch-all 200 误报）
    s, _, b = get(base + '/druid/index.html')
    if s == 200 and 'druid' in b.lower():
        hits.append(('Druid 控制台 (/druid/index.html)', '未授权直接进；登录页就试 druid 弱口令'))
    s, hh, b = get(base + '/manager/html')
    www = str(hh.get('WWW-Authenticate', hh.get('www-authenticate', '')))
    if (s == 401 and 'basic' in www.lower()) or (s == 200 and 'tomcat' in b.lower()):
        hits.append(('Tomcat Manager (/manager/html)', '401 试弱口令 tomcat/s3cret；200 直接部署 war'))

    # 通用：指纹头
    for h in ('x-powered-by', 'server'):
        if h in hd_low:
            print('[i] header %s: %s' % (h, hd_low[h]))

    if not hits:
        print('\n[-] 五特征全空：15 分钟止损原则，撤（防御侧照常走真修复/通防）')
        return
    print('\n[+] 命中 %d 个特征：' % len(hits))
    for name, nxt in hits:
        print('  ● %s\n    → %s' % (name, nxt))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    probe(sys.argv[1])
