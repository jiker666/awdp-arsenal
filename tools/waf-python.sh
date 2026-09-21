#!/bin/sh
# ============================================================
# 03 Python/Flask 通防 · sitecustomize 挂 WSGI 中间件
# ------------------------------------------------------------
# 原理：解释器启动时自动 import sitecustomize；hook 住 flask 导入，
#       给 Flask.wsgi_app 包一层全局过滤，不碰应用源码
# 生效：只对新进程生效——杀掉 werkzeug reloader 的子进程（父进程自动拉新，
#       容器不重启）。gunicorn/uvicorn 部署需自行重启服务进程
# 撤销：rm <site-packages>/sitecustomize.py 再杀一次 reloader 子进程
# ============================================================
SP=$(python3 -c 'import site; print(site.getsitepackages()[0])' 2>/dev/null)
[ -z "$SP" ] && { echo "[oneshot] no site-packages"; exit 0; }

cat > "$SP/sitecustomize.py" <<'EOF'
import builtins
import io
from urllib.parse import unquote_plus

_orig_import = builtins.__import__
_patched = False
# 特征按判据调：SSTI 题{{/lipsum；反序列化题换 pickle/eval 等
_BAD = (b'{{', b'lipsum', b'cycler', b'__globals__', b'__subclasses__', b'popen')

def _waf(environ, start_response):
    qs = unquote_plus(environ.get('QUERY_STRING', ''))
    try:
        ln = int(environ.get('CONTENT_LENGTH') or 0)
        raw = environ['wsgi.input'].read(ln) if ln > 0 else b''
        environ['wsgi.input'] = io.BytesIO(raw)          # 塞回去给应用
        body = unquote_plus(raw.decode('utf-8', 'replace'))
    except Exception:
        body = ''
    text = (qs + '\n' + body).encode('utf-8', 'replace')  # 先解码再查，防 %7B%7B 躲
    for b in _BAD:
        if b in text:
            start_response('403 Forbidden', [('Content-Type', 'text/plain')])
            return [b'blocked by oneshot waf']
    return None

def _hook(name, *a, **k):
    global _patched
    mod = _orig_import(name, *a, **k)
    if not _patched and name == 'flask':
        _patched = True
        try:
            import flask
            _orig_wsgi = flask.Flask.wsgi_app
            def wsgi_app(self, environ, start_response):
                r = _waf(environ, start_response)
                if r is not None:
                    return r
                return _orig_wsgi(self, environ, start_response)
            flask.Flask.wsgi_app = wsgi_app
        except Exception:
            pass
    return mod

builtins.__import__ = _hook
EOF

# 让 sitecustomize 生效：touch 入口文件，reloader 自己换子进程
# （直接 kill 子进程会连带 reloader 父进程退出→容器重启→被判"服务搞崩"；
#   werkzeug 只认子进程退出码 3 = "文件变了请重启"，SIGTERM 不算）
for c in /app/app.py /app/main.py /app/server.py /app/wsgi.py; do
    [ -f "$c" ] && touch "$c" && echo "[oneshot] touched $c (reloader restarts)" && break
done
echo "[oneshot] python waf installed at $SP/sitecustomize.py"
