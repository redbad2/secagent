---
name: domain-security-analysis
trigger: domain
created: 2026-07-09T00:00:00
updated: 2026-07-11T00:00:00
---

## 域名安全分析 SOP（16 节点）

分析域名时按以下节点逐项执行，每项完成后标记状态，确保不遗漏。

---

### 节点 1：node_whois — WHOIS 注册信息

调用 secagent__domain_whois、qianxin_fdp__whois_domain_history

**判断规则：**
- 注册时间 < 7 天 → 高度可疑
- 注册商为隐私保护服务 → 中性，需结合其他信息
- 域名进入赎回期后重新激活 → 可能是域名劫持
- 注册商频繁变更 → 可能在转移基础设施
- 注册人姓名与域名高度相似（WHOIS SLD 相似度 > 0.9）→ 大概率合法注册

---

### 节点 2：node_rdata — RDATA 解析记录

调用 qianxin_fdp__flint_rrset

**判断规则：**
- 记录 GEO 位置与 ICP 备案地不符 → 需关注
- 访问数量极低（access_count < 100）→ 可能是定向攻击基础设施
- 记录类型异常（如大量 TXT 记录）→ 可能是 DNS 隧道
- 多个子域名解析到同一 IP → 需检查该 IP 是否为 CDN

---

### 节点 3：node_page — 页面内容检查

调用 web_fetch__fetch、qianxin_fdp_domain__webdb

**判断规则：**
- 页面返回 403/404/503 → 域名可能未实际部署
- 页面包含登录表单 + 品牌标识（Google/银行/社交平台）→ 钓鱼
- 页面重定向到其他域名 → 追踪重定向链
- 页面内容为空或只有框架 → 可能是恶意基础设施占位页
- 页面标题与域名语义不相关 → 需关注

---

### 节点 4：node_client — 客户端访问统计

调用 ctia_domain__domain_client、ctia_domain__client_geo

**判断规则：**
- 客户端数量 ≤ 100 → 低流量，可能是定向攻击或新部署
- 客户端地理分布高度集中（单一国家 > 90%）→ 可能是区域性威胁
- 客户端数量突然激增 → 可能是攻击活动扩大
- 客户端离散度低（同 IP 段大量访问）→ 可能是扫描或僵尸网络

---

### 节点 5：node_float — 域名流行度

调用 qianxin_fdp_domain__float_fqdn

**判断规则：**
- 流行度排名前 1000 → 极低概率为恶意
- 流行度排名 1000-100000 → 中等可信度，需结合其他信息
- 流行度排名 > 100000 或无数据 → 需要更仔细分析
- 流行度极低 + 威胁标签 → 高风险信号

---

### 节点 6：node_flint — PDNS 生命周期

调用 qianxin_fdp__flint_rrset（关注时间字段）

**判断规则：**
- last_seen 距今 > 180 天 → 域名可能已停止使用
- f_duration（首次到最近观测时间跨度）< 7 天 → 新出现的域名
- fit_count（观测次数）极低 → 低活跃度
- 子域名命名模式异常（随机字符、连续数字）→ 可能是 DGA

---

### 节点 7：node_icp — ICP 备案信息

调用 secagent__domain_libra_report（包含 ICP 数据）

**判断规则：**
- 有合法 ICP 备案 → 强安全信号（降低风险）
- ICP 备案号与域名主体不匹配 → 需关注
- 无 ICP 备案但解析到国内 IP → 需关注（可能违规）
- ICP 备案号对应已注销企业 → 高风险

---

### 节点 8：node_domain — 域名字符串分析

直接分析域名字符串特征

**判断规则：**
- 域名模仿知名品牌（如 g00gle、paypa1）→ 高度可疑
- 域名包含随机字符（如 x7k9m2.xyz）→ 可能是 DGA
- 域名包含敏感关键词（如 login、secure、verify、update）→ 钓鱼信号
- 域名长度异常（> 30 字符）→ 需关注
- 使用非主流 TLD（.xyz/.top/.buzz/.club）→ 风险略高

---

### 节点 9：node_fdark — 样本关联

调用 ctia_domain__sample_downloader、secagent__domain_threat

**判断规则：**
- 有已知恶意样本通过该域名下载 → 高风险
- 沙箱检测率 > 50% → 高度可疑
- 沙箱检测率 < 5% → 可能是误报
- 样本类型为 PE/ELF/APK → 需进一步分析样本行为

---

### 节点 10：node_cert — TLS 证书分析

调用 qianxin_fdp__certdb_domain

**判断规则：**
- 自签证书 → 中性（不一定是恶意，但降低了可信度）
- Let's Encrypt 免费证书 → 中性
- 证书 SAN 包含大量不相关域名 → 共享主机或 CDN
- 证书有效期极短（< 30 天）→ 可能是自动化恶意基础设施
- 证书已过期 → 域名可能已废弃

---

### 节点 11：node_cyberspace — 网络空间测绘

调用 hunter_mcp__hunter_search

**搜索语法：**
```
搜索同 IP 的其他域名：ip:"目标IP"
搜索同 ASN 的资产：as_org:"Organization Name"
指定返回字段：fields="ip,port,domain,web_title,protocol,status_code,component,vul_list"
```

**判断规则：**
- 同 IP 上有多个恶意域名 → 目标域名风险升高
- 开放端口异常（445/3389/22 等管理端口）→ 配置不当或扫描目标
- 服务组件有已知 CVE → 漏洞风险
- 非标准端口（8080/8443）运行 Web 服务 → 需关注

---

### 节点 12：node_web_search — 公开情报搜索

调用 exa__web_search_exa

**搜索策略：**
- 搜索 "域名 + malicious/phishing/scam" → 查找安全报告
- 搜索 "域名 + 安全/威胁" → 查找中文情报
- 搜索回退：复合条件无结果时，回退为仅搜索域名本身

---

### 节点 13：node_ti — 多源威胁情报

调用 ctia_domain__v1_domain、secagent__domain_threat、qianxin_fdp__ioc

**判断规则：**
- 多个独立来源都标记为恶意 → 高置信度
- 单一来源标记，其他来源无异常 → 低置信度，需进一步验证
- 标签置信度 < 30% → 基本是噪声，忽略
- CTIA white 标签 ≠ 安全，只是"未被标记为恶意"

---

### 节点 14：node_codomain — 伴生域名关联

调用 secagent__codomain_analysis、qianxin_fdp_domain__codomain

**判断规则：**
- 伴生域名多为已知恶意域名 → 目标域名风险升高
- 伴生域名 count_days 高 → 关联强度高
- 伴生域名字符相似度高 → 可能是同一运营者的域名簇
- 伴生域名均为正常业务域名 → 降低风险

---

### 节点 15：node_followup — 后续分析问题

基于前 14 个节点的发现，提出值得深入分析的问题：
- 发现异常 IP → 追查该 IP 的其他域名
- 发现可疑注册商 → 检查同注册商的其他域名
- 发现 DGA 特征 → 搜索同模式的其他域名
- 发现 C2 特征 → 关联分析同家族的其他 C2

---

### 节点 16：node_summary — 综合评估

**评分框架：**

| 信号 | 权重 |
|------|------|
| CTIA 恶意标签（多源一致） | 高 |
| 域名年龄 < 7 天 | 高 |
| DGA/随机字符串特征 | 高 |
| 钓鱼页面确认 | 高 |
| ICP 备案 + 域名注册 > 5 年 | 降低 |
| 知名 CDN/WAF | 降低 |
| 高流行度排名 | 降低 |
| 低置信度标签（< 30%） | 忽略 |

**输出格式：**
- 风险等级：低 / 中 / 高 / 严重
- 置信度：0.0 - 1.0
- 关键发现列表
- IOC 列表
- 处置建议
