package awdp.filter;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * AWDP Java 通用过滤（RASP-lite）：@WebFilter 注解挂全局，不需要改 web.xml（Servlet 3.0+）。
 *
 * 拦截对象 = 04_攻击套路"五特征"对应的入口特征：
 *   jndi/ldap/rmi  -> log4j / JNDI 注入
 *   @type          -> fastjson/jackson 反序列化
 *   rO0AB / aced0005 -> 原生 Java 反序列化（base64 / hex 魔数）
 *   ${...}         -> SPEL/EL/模板注入
 * 黑名单调参原则：对着 checker 的 payload 关键词加，宁可漏放不可误杀（误杀 SLA = 判负）。
 *
 * ⚠️ 已知局限（改这里之前先读）：
 *   - 只查 query/param/cookie/header，**不读 POST body**（JSON 体的 fastjson payload 拦不到；
 *     body 检查要包 HttpServletRequestWrapper 缓存流，交给赛场 Qwen 补，或直接换 fastjson jar）
 *   - 真正的修复优先级：换单个有漏洞的 jar > 本 Filter（Filter 是规则空白时的兜底）
 */
@WebFilter(filterName = "awdpFilter", urlPatterns = "/*")
public class AwdpFilter implements Filter {

    // 全部小写；匹配前输入也 toLowerCase
    private static final String[] BLACK = {
        "jndi:", "ldap:", "rmi:", "dns:",             // JNDI/log4j
        "@type",                                       // fastjson/jackson
        "rO0AB", "aced0005",                           // 原生反序列化魔数
        "${",                                          // SPEL/EL
        "getruntime", "processbuilder", "invoke",      // 反射链常用词（按需增删）
    };

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest  hreq  = (HttpServletRequest) req;
        HttpServletResponse hresp = (HttpServletResponse) resp;

        if (dirty(hreq.getQueryString())) return deny(hresp);

        for (String[] vals : hreq.getParameterMap().values()) {
            for (String v : vals) if (dirty(v)) return deny(hresp);
        }
        if (hreq.getCookies() != null) {
            for (javax.servlet.http.Cookie c : hreq.getCookies()) {
                if (dirty(c.getValue()) || dirty(c.getName())) return deny(hresp);
            }
        }
        if (dirty(hreq.getHeader("X-Api-Version")) || dirty(hreq.getHeader("Referer"))
                || dirty(hreq.getHeader("User-Agent")) || dirty(hreq.getHeader("Accept"))) {
            return deny(hresp);
        }
        chain.doFilter(req, resp);
    }

    private boolean dirty(String s) {
        if (s == null) return false;
        String low = s.toLowerCase();
        for (String b : BLACK) if (low.contains(b)) return true;
        return false;
    }

    private HttpServletResponse deny(HttpServletResponse resp) throws IOException {
        resp.setStatus(403);
        resp.setContentType("text/plain; charset=utf-8");
        resp.getWriter().write("forbidden");
        return resp;
    }

    @Override public void init(FilterConfig cfg) {}
    @Override public void destroy() {}
}
