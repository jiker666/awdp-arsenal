#!/bin/sh
# ============================================================
# 02 PHP 通防 · auto_prepend_file 全局输入过滤
# ------------------------------------------------------------
# 原理：往 PHP conf.d 塞一个 ini，让每个请求先跑 WAF，不碰应用源码
# 生效：apache mod_php 用 graceful 平滑重载（fpm 部署需 php-fpm reload）
# 撤销：rm /usr/local/etc/php/conf.d/zz_oneshot.ini /usr/local/etc/php/zz_oneshot_waf.php && apachectl -k graceful
# 调参：误杀 SLA 就从 $__bad 里删关键字；探针还漏就往里加
# ============================================================
mkdir -p /usr/local/etc/php/conf.d

cat > /usr/local/etc/php/zz_oneshot_waf.php <<'EOF'
<?php
// oneshot waf: 全局拦 GET/POST/COOKIE 里的注入特征
$__bad = array('$(', '${', '`', 'flag', ';', '|', "\n", "\r");
foreach (array($_GET, $_POST, $_COOKIE) as $__src) {
    foreach ($__src as $__v) {
        if (is_array($__v)) $__v = implode(' ', $__v);
        $__low = strtolower((string)$__v);
        foreach ($__bad as $__b) {
            if (strpos($__low, $__b) !== false) {
                http_response_code(403);
                header('Content-Type: text/plain');
                die('blocked by oneshot waf');
            }
        }
    }
}
EOF

echo "auto_prepend_file=/usr/local/etc/php/zz_oneshot_waf.php" > /usr/local/etc/php/conf.d/zz_oneshot.ini

apachectl -k graceful 2>/dev/null || apache2ctl graceful 2>/dev/null || true
echo "[oneshot] php waf installed"
