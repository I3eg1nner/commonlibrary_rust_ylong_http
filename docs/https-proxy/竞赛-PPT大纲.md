# 竞赛 PPT 制作大纲 —— ylong_http_client HTTPS 代理支持

> 共 15 页。每页含:标题 / 要点 / 建议视觉 / 口播备注一句。评分导向:任务完成度30% · 技术先进性25% · 性能指标20% · 开源规范性15% · 答辩展示10%。所有性能数字保持诚实框架。

---

### 1. 封面
- 要点:
  - 标题「为 ylong_http_client 增加 HTTPS 代理支持(TLS-in-TLS)」
  - 副标题:安全的 TLS 代理 · 可扩展代理模块 · RISC-V 真机性能认证
  - 队名 / 成员 / 日期(2026-07)
  - 一句话定位:基于自研 OpenSSL FFI,无新增第三方依赖
- 建议视觉:项目 Logo + 两层 TLS 嵌套的极简示意
- 口播:我们为 ylong_http_client 补齐了 HTTPS 代理能力,并以严谨的性能实测为它背书。

### 2. 问题与价值
- 要点:
  - 原状:只支持明文 HTTP 代理,HTTPS 目标的 CONNECT 隧道跑在**未加密 TCP** 上
  - 痛点1:代理凭据 `Proxy-Authorization` 与 CONNECT 元数据明文暴露
  - 痛点2:无法用于强制 TLS 代理的企业/受控环境
  - 痛点3:代理逻辑内联在连接器,难扩展;从未与 libcurl 对标
- 建议视觉:左「明文隧道(红色警示)」vs 右「TLS 隧道(绿色加锁)」对比图
- 口播:代理这一跳不加密,凭据就在网上裸奔——这是我们要解决的核心问题。

### 3. 目标拆解(三档子任务)
- 要点:
  - 子任务1:HTTPS 代理 + 单向/双向证书验证 + 完整代理 TLS 配置
  - 子任务2:代理功能模块化,保证新增协议可扩展
  - 子任务3:与 libcurl 对比,HTTPS 代理场景性能 ≥20%
  - 例外(诚实声明):HTTP/3 与同步 HTTPS 代理不在赛题范围;原有接口不受影响
- 建议视觉:三档任务卡片表格,右栏标注「完成 / 完成 / 场景达成」
- 口播:三个子任务对应技术、架构、性能三个维度,我们逐一交付。

### 4. 架构总览(图)
- 要点:
  - 三层职责:选择层(util/proxy)/ 隧道层(async_impl/proxy)/ 连接层(connector)
  - 选择层协议无关;隧道层是唯一扩展点;连接层对「代理是否加密」无感知
  - 数据流:match_proxy → ProxyKind → TunnelConnect → ProxyTunnel → 目标 TLS
- 建议视觉:方案文档 §3 的三层 ASCII 架构图重绘为分层框图,`★` 标新增点
- 口播:职责单一的三层结构,让「代理加密与否」被彻底隔离在隧道层。

### 5. TLS-in-TLS 原理
- 要点:
  - 两层 TLS:TLS①(到代理)包裹 CONNECT,TLS②(到目标)嵌套在 TLS① 内
  - 步骤:代理 TLS 握手 → TLS 内发 CONNECT → 200 → 目标 TLS 握手(嵌套)
  - 凭据只在 TLS① 内传输,不再明文
  - 类型天然可行:`AsyncSslStream<S>` 对内层流泛型,只需 `ProxyTunnel` 实现读写
- 建议视觉:方案文档 §3.1 的嵌套 TLS 时序/管道图
- 口播:两层 TLS 层层嵌套,靠的是 SSL 流本就对内层流泛型这一现成条件。

### 6. 代理模块与 Trait 抽象(可扩展性)
- 要点:
  - `trait TunnelConnect { fn tunnel(..) -> ProxyTunnel }` 统一接口
  - `HttpProxyTunnel`(明文)/ `HttpsProxyTunnel`(TLS)两个实现
  - `connect_tunnel<S>` 对底层流泛型,明文/加密复用同一 CONNECT 逻辑
  - **新增 SOCKS = 加一个 trait 实现 + 一个 ProxyKind 分支,连接器不改**
- 建议视觉:`TunnelConnect` 代码片段 + 「加 SOCKS 只需两步」箭头图
- 口播:扩展点被收敛成一个 trait,加新协议是加法而非改造。

### 7. 核心技术亮点(mTLS / ALPN / FFI)
- 要点:
  - 自研 `c_openssl` FFI,**零新增第三方 TLS 依赖**
  - mTLS 补齐硬伤:原缺私钥设置能力 → 新增 FFI `SSL_CTX_use_PrivateKey_file` + `SSL_CTX_check_private_key` → `private_key_file`
  - 完整代理 TLS:CA、客户端证书+私钥、版本范围、算法套件、SNI、ALPN
  - ALPN 转为公开 API:`alpn_protocols(&["h2","http/1.1"])`,仅作用于代理这一跳
- 建议视觉:`TlsConfig::builder()...alpn_protocols(..)` 配置代码截图,高亮新增行
- 口播:没有私钥就没有双向认证——我们把这条缺失的 FFI 链路补全了。

### 8. 工程质量(两运行时 + 测试矩阵)
- 要点:
  - 两运行时均通过:tokio(6 例)+ ylong_runtime(1 例,`ylong_base,tls_default`)
  - 单元测试(CONNECT 200/407/超长/错误)+ 同步 1 例
  - 回归:async lib 107 / 136,sync lib 152;`cargo clippy` 干净
  - async/sync × tls 全组合可编译(顺带修复基线 sync 与 no-tls 编译损坏)
- 建议视觉:测试矩阵表格(层次 × 文件 × 结果 全绿)
- 口播:赛题要求两种运行时都能跑,我们都跑通了,且全组合编译干净。

### 9. 性能:方法学
- 要点:
  - 拓扑:client ─TLS→ TLS 代理 ─CONNECT→ TLS 源(TLS-in-TLS),loopback 自启
  - 关键区分:**libcurl 库**(`curl` crate 同进程复用 Easy)vs **curl CLI**(含进程开销,会高估)
  - 公平性:两端链接同一份系统 OpenSSL,同样验证证书;进程隔离 + taskset 绑核
  - **两套互补基准**:①自研对比型 `https_proxy_bench`(RPS + P50/P90/P99/P99.9 + `BENCH_DELAY_MS` 时延维度);②criterion 统计型 `https_proxy_criterion`(单请求时延带置信区间/离群点检测,实测 ~155–169 µs)
- 建议视觉:拓扑图 + 「两种 libcurl 口径」对比小表 + 两套基准分工示意
- 口播:先把测法钉死——库对库、同一 OpenSSL、进程隔离,再用 criterion 给单点时延加上统计置信度。

### 10. 性能:单连接持平的诚实结论 + perf 根因
- 要点:
  - 单连接 vs libcurl 库:~4,310 vs ~4,237 req/s,**≈+1.5%(持平)**,≥20% 未达成
  - perf:同密码套件 ChaCha20、指令数几乎相同(21.3B vs 21.1B)
  - 唯一差异:上下文切换 110,794 vs 3,407(≈33×)——多线程运行时跨线程唤醒,嵌套 TLS 翻倍
  - 改单线程运行时后 110k→4k(≈libcurl),根因确认;早先 −35%/+26%/+41.5% 均为假象,已撤回
- 建议视觉:perf stat 对比条形图(指令数持平 / 上下文切换 33×)
- 口播:单连接两端都被 OpenSSL 卡住,快不了 20%——我们如实说,并用 perf 找到真因。

### 11. 性能:高并发受限 CPU ≥20%(RISC-V 图)
- 要点:
  - 场景:受限 CPU 主机(客户端钉单核)承载大量并发 keep-alive 连接
  - ylong 单线程运行时(一个 epoll 反应堆)vs libcurl 每连接一线程(K 个 OS 线程超额订阅)
  - RISC-V 实测:K=50/200/500/1000 稳定 **≈+30%**,两轮可复现(轮间差 <2.5pt)
  - x86 佐证 +22%…+38%;K=1 持平(无多路复用可吃)
- 建议视觉:K vs 吞吐折线图(ylong 明显高于 libcurl-threads),标注 +30%
- 口播:异步真正的主场是海量连接少线程——这里我们稳稳达成 ≥20%。

### 12. P99 与时延维度
- 要点:
  - 基准输出 P50/P90/P99/P99.9 分位,不止平均值
  - 单连接单请求延迟:ylong ≈0.23ms / libcurl 库 ≈0.24ms / curl CLI ≈0.31ms
  - `BENCH_DELAY_MS` 注入源端时延探测网络维度:注入 2ms 后单连接差距 −60%→−3%
  - 结论:时延一旦成为主导,数据路径差异被淹没,进一步印证「非数据路径瓶颈」
- 建议视觉:P50/P90/P99/P99.9 分位柱状 + 时延注入前后差距收窄示意
- 口播:我们看的是尾延迟和网络维度,而不是只报一个好看的平均数。

### 13. 与 libcurl 对比总表
- 要点:
  - 单连接(vs 库):持平 ≈+1.5%
  - 高并发受限 CPU(vs threads):≈+30%(RISC-V,达成 ≥20%)
  - vs curl CLI:+26%(仅参考,非库对比)
  - vs curl_multi:**未认证**(指示性驱动平台敏感,不主张优势)
- 建议视觉:四行对比总表,达成项绿、未认证项灰并注明原因
- 口播:一张表说清我们赢在哪、平在哪、以及哪块我们诚实地不下结论。

### 14. 社区贡献与 PR 就绪
- 要点:
  - 公共 API 仅 additive(`tls_config` / `private_key_file` / 公开 `alpn_protocols`),不破坏签名
  - 附示例 `async_proxy_https.rs`、模块级 rustdoc(含「如何加代理协议」)、benchmark 方法学
  - 顺带修复基线 sync 与 no-tls 编译损坏,全组合可编译,改动以 `#[cfg]` 门控
  - OpenSpec change 完整(proposal / design / tasks / benchmark-results)且 validate 通过
- 建议视觉:文件清单 + 「additive API / 全组合编译 / 文档齐全」三枚就绪徽章
- 口播:改动是加法、有文档有示例、能干净编译——随时可提社区 PR。

### 15. 总结与展望
- 要点:
  - 三子任务:HTTPS 代理与 mTLS 完成 / 模块化可扩展完成 / 性能场景达成 ≥20% 且如实界定
  - 核心价值:安全(凭据进 TLS)+ 可扩展(TunnelConnect)+ 可信(严谨诚实的性能)
  - 展望:实现 SOCKS(验证抽象)、单线程运行时/绑核作为少连接优化开关、对 curl_multi 做 `socket_action`+epoll 严谨对比
  - 一句话:能证明的才写,撤回一切经不起复核的数字
- 建议视觉:三子任务完成度雷达图 + 展望路线条
- 口播:我们交付了能力,更交付了可被复核的诚实——这是工程可信度的底色。
