# tools/java/ · Java 题防御兜底

⚠️ **未实测**：模板按 Servlet 3.0+ 标准写，没在真实比赛 war/jar 上跑过。
首次使用先在本地（或赛场拿一道题）验证编译和功能，再当通用件使。

## AwdpFilter.java 是什么

一个 `@WebFilter("/*")` 全局过滤器（RASP-lite）：请求的 query / 参数 / cookie /
常用 header 里命中黑名单关键词（jndi:、@type、rO0AB、aced0005、`${`、反射链词）就 403。
黑名单对着 checker 的 payload 调，宁可漏放不可误杀。

**已知局限**：不读 POST body —— fastjson JSON 体的 `@type` 在 body 里，这个 Filter 拦不到。
要拦 body 得用 HttpServletRequestWrapper 缓存请求流再放行（赛场让 Qwen 补 ~30 行），
或者干脆走正道：**把有漏洞的 jar 换成修复版本**（这才是 Java 题的首选修复，见 02 §3.4）。

## 怎么用

### war 包题（最常见）

```sh
# 1. 解包
mkdir webapp && cd webapp && unzip ../challenge.war
# 2. 编译（servlet-api 从解包出来的 WEB-INF/lib 里找，或用本地 Tomcat 的）
javac -cp WEB-INF/lib/*:/usr/local/tomcat/lib/servlet-api.jar \
      -d WEB-INF/classes ../AwdpFilter.java
# 3. 回包（保持原有结构，别用 jar cvf 从外面套）
jar cvf ../fixed.war .
```

`@WebFilter` 注解在 Servlet 3.0+ 容器（Tomcat 7+）自动生效，不用改 web.xml。
如果题目的 web.xml 是老版本声明式，加：

```xml
<filter><filter-name>awdpFilter</filter-name>
  <filter-class>awdp.filter.AwdpFilter</filter-class></filter>
<filter-mapping><filter-name>awdpFilter</filter-name><url-pattern>/*</url-pattern></filter-mapping>
```

### Spring Boot jar 题

不能直接塞 class —— 要么用 Spring Boot 项目重新打包加
`FilterRegistrationBean`（赛前备好空项目模板），要么放弃 Filter 走"换单个 jar"路线。

## 交包

`update.sh` 里 cp 覆盖 war（或按题目要求单文件），重启看平台——多数 Java 题
平台自己会重启服务。打包用 `../make_package.sh`，交前 `../lint_package.sh` 过一遍。
