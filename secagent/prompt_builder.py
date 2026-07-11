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

输出格式：
分析完成后，在回复的最末尾用以下 JSON 格式输出最终结论（用 ```json 包裹）：
```json
{
  "risk_level": "低|中|高|严重",
  "confidence": 0.0,
  "findings": ["发现1", "发现2"],
  "iocs": [],
  "tools_used": [],
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
            parts.append(skill.content)
            parts.append("")

    # 当前任务
    parts.append("--- 当前任务 ---")
    parts.append(f"目标: {target}")
    parts.append(f"类型: {target_type}")
    parts.append(f"分析深度: {depth}")

    depth_map = {
        "quick": "快速分析：仅查询威胁情报，跳过浏览器访问和父域名追溯",
        "standard": "标准分析：执行完整技能流程",
        "deep": "深度分析：标准分析 + 关联资产查询 + 历史对比 + 多角度交叉验证",
    }
    parts.append(depth_map.get(depth, depth_map["standard"]))

    return "\n".join(parts)
