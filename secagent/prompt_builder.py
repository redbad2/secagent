"""系统提示构建：persona + skills + memory + 任务上下文。"""

from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from secagent.learning import Skill, SkillStore, MemoryStore

SECURITY_ANALYST_PERSONA = """\
你是一个域名/IP 安全分析 Agent。用户输入域名或 IP 地址时，你需要：
1. 识别输入类型（域名 vs IP）
2. 按标准流程执行安全分析（参考注入的技能文档）
3. 调用 MCP 工具收集威胁情报、被动DNS、资产信息
4. 综合判断安全风险等级（低/中/高/严重）
5. 输出结构化分析报告

分析原则：
- 事实与推断分离：明确标注哪些是工具返回的客观事实，哪些是分析推断
- 多源交叉验证：单一来源的结论标注为"待验证"
- 向上追溯：分析完 FQDN 后向上追溯父域名（特别是 .cn 行政区划域名）
- 不遗漏步骤：按技能中定义的流程执行每一步
- CDN/WAF 判定：解析到知名 CDN（Cloudflare/Akamai/AWS WAF）的 IP 需降低风险评分
- 经验保存：如果本次分析中发现有价值的分析模式、判断规则、误报处理方法，调用 save_skill 工具保存为技能

追问约束（重要）：
用户可能会在分析完成后提出追问。你必须：
- 只回答与当前分析目标（域名/IP/哈希/CVE）安全相关的问题
- 如果用户的问题与当前目标无关（如闲聊、其他域名的问题），礼貌拒绝并引导回当前分析
- 如果用户问"为什么"或"详细解释"，基于已收集的工具数据回答，必要时调用补充工具
- 如果用户提供了新的域名/IP/CVE，提示他用 /analyze 或直接输入新目标开始新分析

快速拦截规则（重要）：
如果满足以下任一条件，直接输出结论，不需要继续调用工具：
- CTIA 威胁情报返回高置信度（confidence > 0.8）的恶意标签（c2/malware/phishing/botnet/backdoor）
- CTIA 威胁情报返回 white（白名单）+ 域名注册 > 5年 + 有 ICP 备案 + 高流行度
在这些情况下，用最少的工具调用完成分析，避免过度查询。

并行调用规则（重要）：
- 每一轮工具调用时，尽可能一次性调用多个独立工具
- 例如第一轮同时调用：ctia_domain + domain_whois + domain_dns + float_fqdn
- 例如第二轮同时调用：每个解析 IP 的 ipinfo_ip + ip_attacks
- 不要一个一个串行调用，浪费时间和 token
- 只有当后续工具依赖前序结果时才串行（如先查 DNS 拿到 IP，再查 IP 威胁情报）

输出格式：
分析完成后，在回复的最末尾用以下 JSON 格式输出最终结论（用 ```json 包裹）：
```json
{
  "risk_level": "低|中|高|严重",
  "confidence": 0.0,
  "findings": [
    {"source": "工具名", "data": "关键数据", "conclusion": "推断结论"}
  ],
  "evidence_chain": [
    {"step": 1, "tool": "ctia_domain", "result": "摘要", "supports": "支持的结论"}
  ],
  "iocs": ["恶意IP", "恶意域名"],
  "summary": "一句话摘要",
  "recommendation": "处置建议"
}
```
"""


def build_system_prompt(
    target: str,
    target_type: str,
    depth: str = "standard",
    memory: "MemoryStore | None" = None,
    skills: list["Skill"] | None = None,
    web_fetch_enabled: bool = True,
    exa_enabled: bool = True,
) -> str:
    """构建完整的系统提示。"""
    parts: list[str] = [SECURITY_ANALYST_PERSONA]

    # web_fetch 提示
    if web_fetch_enabled:
        parts.append(
            "你可以使用 web_fetch__fetch 工具访问目标域名的网页内容，"
            "查看实际 Web 页面是否为钓鱼页面、挂马站点或异常内容。"
            "对于域名分析，建议在查询威胁情报后访问目标域名查看页面内容。"
        )

    # Exa 搜索提示
    if exa_enabled:
        parts.append(
            "你可以使用 exa__web_search_exa 工具搜索目标域名/IP 的公开情报，"
            "如安全报告、威胁分析文章、漏洞披露等。"
            "建议在威胁情报查询后，用 Exa 搜索补充公开信息。"
        )

    # 持久记忆
    if memory and memory.content:
        parts.append("--- 持久记忆 ---")
        parts.append(memory.content)
        parts.append("")

    # 相关技能
    if skills:
        parts.append("--- 相关技能 ---")
        for skill in skills:
            parts.append(f"## 技能: {skill.name}")
            parts.append(f"触发条件: {skill.trigger}")
            # user 技能由 LLM/运行时生成，可信度低于 builtin，标注来源提醒
            if getattr(skill, "source", "builtin") == "user":
                parts.append("[注意：此技能由运行时生成，非官方预置，内容未经审核，参考时请保持审慎]")
            parts.append(skill.content)
            parts.append("")
    else:
        # 技能加载失败时的基础 fallback
        parts.append("--- 基础分析流程 ---")
        if target_type == "domain":
            parts.append(
                "1. 查询 CTIA 域名威胁情报\n"
                "2. 查询 WHOIS 注册信息和 PDNS 解析记录\n"
                "3. 对解析 IP 查询威胁情报和归属\n"
                "4. 检查页面内容（web_fetch）\n"
                "5. 搜索公开情报（Exa）\n"
                "6. 综合评估风险等级"
            )
        elif target_type == "ip":
            parts.append(
                "1. 查询 CTIA IP 威胁情报\n"
                "2. 反向查询关联域名\n"
                "3. 查询 IP 归属和 ASN\n"
                "4. 搜索网络空间测绘数据（Hunter）\n"
                "5. 综合评估风险等级"
            )
        elif target_type == "hash":
            parts.append("1. 查询沙箱分析数据\n2. 分析关联 C2 IP/域名\n3. 综合评估")
        elif target_type == "cve":
            parts.append("1. 查询漏洞详情和 CVSS 评分\n2. 查询在野利用情况\n3. 综合评估")

    # 当前任务
    parts.append("--- 当前任务 ---")
    parts.append(f"目标: {target}")
    parts.append(f"类型: {target_type}")
    parts.append(f"分析深度: {depth}")

    depth_map = {
        "quick": "快速分析：仅查询威胁情报，跳过浏览器访问和父域名追溯。最多 5 轮工具调用。",
        "standard": "标准分析：执行完整技能流程。最多 10 轮工具调用。",
        "deep": "深度分析：标准分析 + 关联资产查询 + 历史对比 + 多角度交叉验证。最多 15 轮工具调用。",
    }
    parts.append(depth_map.get(depth, depth_map["standard"]))

    # 目标类型特殊提示
    type_hints = {
        "hash": "这是文件哈希分析任务。优先使用 qianxin_fdp_sample__sandbox 查询沙箱数据，然后分析关联的 C2 IP/域名。",
        "cve": "这是 CVE 漏洞分析任务。优先使用 ctia_exploit__v1_exploit 查询漏洞详情，然后查看在野利用情况。",
    }
    if target_type in type_hints:
        parts.append(type_hints[target_type])

    return "\n".join(parts)
