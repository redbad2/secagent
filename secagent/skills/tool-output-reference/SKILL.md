---
name: tool-output-reference
trigger: reference,fields,format
created: 2026-07-11T00:00:00
---

## MCP 工具输出字段参考

理解各 MCP 工具返回数据的字段含义，避免误读。

---

### Hunter 网络空间测绘（hunter_mcp__hunter_search）

返回结构：`{code, message, data: {total, arr: [{...资产记录}]}}`

| 字段 | 说明 |
|------|------|
| ip | IP 地址 |
| port | 端口号 |
| domain | 关联域名 |
| url | 完整访问 URL |
| protocol | 应用层协议（http/https/ftp） |
| status_code | HTTP 状态码（非 Web 资产为 0） |
| web_title | 网页标题 |
| header_server | Server 头（如 cloudflare、nginx） |
| banner | 服务 Banner |
| country / province / city | 地理位置 |
| isp | 运营商 |
| as_org | ASN 组织名 |
| ip_tag | IP 标签（如 CDN） |
| is_web | 是否为 Web 资产 |
| component | 组件列表 [{name, version}] |
| vul_list | 漏洞列表 |
| cert_sha256 | 证书哈希 |
| ssl_certificate | SSL 证书内容 |

**注意：** 非 Web 资产可能缺少 header、web_title 等字段。

---

### CTIA 域名情报（ctia_domain__v1_domain）

| 字段 | 说明 |
|------|------|
| domain | 域名 |
| risk_level | 风险等级 |
| tags | 标签列表 |
| tag_confidence | 标签置信度 |
| first_seen | 首次发现时间 |
| last_seen | 最近发现时间 |

**判断：** tags 为 white ≠ 安全，只是"未被标记为恶意"。

---

### CTIA IP 情报（ctia_ip__ipinfo_ip）

| 字段 | 说明 |
|------|------|
| ip | IP 地址 |
| geo | 地理位置 |
| asn | ASN 号 |
| as_org | ASN 组织 |
| risk_level | 风险等级 |
| tags | 标签列表 |
| ptr | PTR 记录 |

---

### FDP PDNS（qianxin_fdp__flint_rrset）

| 字段 | 说明 |
|------|------|
| rrname | 请求的域名 |
| rtype | DNS 记录类型（1=A, 5=CNAME, 28=AAAA） |
| rdata | 解析值 |
| first_seen | 首次观测时间 |
| last_seen | 最近观测时间 |
| count | 观测次数 |

---

### FDP WHOIS（qianxin_fdp__whois_domain_history）

| 字段 | 说明 |
|------|------|
| registrar | 注册商 |
| registrant_name | 注册人姓名 |
| registrant_org | 注册人组织 |
| registrant_email | 注册人邮箱 |
| created_date | 创建时间 |
| expires_date | 过期时间 |
| updated_date | 更新时间 |
| nameservers | 域名服务器列表 |

---

### FDP 流行度（qianxin_fdp_domain__float_fqdn）

| 字段 | 说明 |
|------|------|
| float | 流行度得分（0-10，越大越流行） |
| rank | 排名（1 = 最流行） |

**参考：** float=9.99 排名第 1（千亿级日访问），float=5.86 排名 100 万（万级日访问）

---

### Libra 域名报告（secagent__domain_libra_report）

包含 PDNS + WHOIS + ICP + 样本 + 流行度的综合数据。

| 字段 | 说明 |
|------|------|
| rdata_list | 历史解析记录 |
| whois | WHOIS 摘要 |
| icp | ICP 备案信息 |
| float | 流行度 |
| fdark | 样本关联 |
| client | 客户端统计 |
| tags | 威胁标签 |
| codomain | 伴生域名 |
