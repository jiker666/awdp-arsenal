#!/bin/sh
# ============================================================
# 04 Node/Express 通防 · 注入全局中间件
# ------------------------------------------------------------
# 原理：Node 没有全局钩子，只能在入口文件 express body 解析器后
#       注入一段中间件（nodemon/pm2 检测到文件变化自动重启生效）
# 撤销：还原 app.js（平台回滚只还原服务文件的话会自动带走）
# 注意：'constructor/prototype' 全局拦有误杀概率（正常内容含这词就 403），
#       交之前先过一遍 SLA
# ============================================================
APP=""
for c in /app/app.js /app/index.js /app/server.js /srv/app.js; do
    [ -f "$c" ] && APP="$c" && break
done
[ -z "$APP" ] && APP=$(ls /app/*.js 2>/dev/null | head -1)
[ -z "$APP" ] && { echo "[oneshot] no node entry found"; exit 0; }

node - "$APP" <<'EOF'
const fs = require('fs');
const f = process.argv[2];
let s = fs.readFileSync(f, 'utf8');
if (s.includes('__oneshot__')) { console.log('[oneshot] already patched'); process.exit(0); }
const INJ = `
//__oneshot__ waf
app.use(function(req,res,next){
  try{
    const t = JSON.stringify(req.query||{}) + JSON.stringify(req.body||{})
            + JSON.stringify(req.params||{}) + decodeURIComponent(req.url||'');
    if (/__proto__|constructor|prototype|outputfunctionname|localsname|child_process|execsync|spawn/i.test(t)) {
      res.status(403).send('blocked by oneshot waf'); return;
    }
  }catch(e){}
  next();
});`;
// 锚点优先级：body 解析器之后（能看到 req.body）> express() 创建之后
const anchors = [
    /app\.use\(express\.urlencoded\([^\n]*\);?/,
    /app\.use\(express\.json\([^\n]*\);?/,
    /=\s*express\(\)/,
];
for (const re of anchors) {
    const m = s.match(re);
    if (m) { s = s.replace(m[0], m[0] + '\n' + INJ); break; }
}
if (s.includes('__oneshot__')) {
    fs.writeFileSync(f, s);
    console.log('[oneshot] node waf injected -> ' + f);
} else {
    console.log('[oneshot] no injection anchor in ' + f);
}
EOF
