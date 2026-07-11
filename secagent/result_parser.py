"""结果解析：从 LLM 最终回复中提取结构化分析结果 + 风险评分。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AnalysisResult:
    """安全分析结果。"""
    target: str
    target_type: str           # "domain" | "ip"
    risk_level: str = "未知"
    confidence: float = 0.0
    findings: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    summary: str = ""
    recommendation: str = ""
    raw_output: str = ""       # LLM 完整回复
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "findings": self.findings,
            "iocs": self.iocs,
            "tools_used": self.tools_used,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }

    def to_markdown(self) -> str:
        """生成 Markdown 格式分析报告。"""
        lines = [
            f"# 安全分析报告: {self.target}",
            "",
            f"| 字段 | 值 |",
            f"|------|-----|",
            f"| 目标 | {self.target} |",
            f"| 类型 | {self.target_type} |",
            f"| 风险等级 | **{self.risk_level}** |",
            f"| 置信度 | {self.confidence:.0%} |",
            f"| 分析时间 | {self.timestamp[:19]} |",
            "",
        ]
        if self.summary:
            lines.append(f"## 摘要")
            lines.append(f"{self.summary}")
            lines.append("")
        if self.findings:
            lines.append(f"## 发现")
            for f in self.findings:
                lines.append(f"- {f}")
            lines.append("")
        if self.iocs:
            lines.append(f"## IOC (入侵指标)")
            for ioc in self.iocs:
                lines.append(f"- {ioc}")
            lines.append("")
        if self.tools_used:
            lines.append(f"## 使用工具 ({len(self.tools_used)})")
            lines.append(", ".join(f"`{t}`" for t in self.tools_used))
            lines.append("")
        if self.recommendation:
            lines.append(f"## 建议")
            lines.append(f"{self.recommendation}")
            lines.append("")
        return "\n".join(lines)


def is_valid_ip(target: str) -> bool:
    """简单 IPv4 校验。"""
    parts = target.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def parse_analysis_result(
    target: str,
    target_type: str,
    llm_output: str,
    tools_used: list[str],
) -> AnalysisResult:
    """从 LLM 最终回复中提取结构化结果。

    LLM 被要求在回复末尾输出 JSON 块，这里负责提取和兜底。
    """
    result = AnalysisResult(
        target=target,
        target_type=target_type,
        raw_output=llm_output,
        tools_used=tools_used,
    )

    # 尝试提取末尾的 JSON 块
    json_blocks = re.findall(r"```json\s*\n(.*?)\n```", llm_output, re.DOTALL)
    if json_blocks:
        try:
            data = json.loads(json_blocks[-1])
            result.risk_level = data.get("risk_level", result.risk_level)
            result.confidence = float(data.get("confidence", 0.0))
            result.findings = data.get("findings", result.findings) or []
            result.iocs = data.get("iocs", result.iocs) or []
            result.summary = data.get("summary", "")
            result.recommendation = data.get("recommendation", "")
            # tools_used 优先用实际记录的
            if data.get("tools_used") and not tools_used:
                result.tools_used = data["tools_used"]
        except (json.JSONDecodeError, ValueError) as e:
            # JSON 解析失败，尝试提取裸 JSON
            _try_extract_bare_json(llm_output, result)
    else:
        _try_extract_bare_json(llm_output, result)

    # 兜底：如果没有 findings，把 LLM 输出截断作为 findings
    if not result.findings and llm_output:
        result.findings = [llm_output[:200] + "..." if len(llm_output) > 200 else llm_output]
        result.summary = result.summary or llm_output[:100]

    return result


def _try_extract_bare_json(text: str, result: AnalysisResult) -> None:
    """尝试从文本中提取裸 JSON（无 ```json 包裹）。"""
    # 找最后一个 { 开头的块
    matches = re.findall(r'\{[^{}]*"risk_level"[^{}]*\}', text, re.DOTALL)
    if matches:
        try:
            data = json.loads(matches[-1])
            result.risk_level = data.get("risk_level", result.risk_level)
            result.confidence = float(data.get("confidence", 0.0))
            result.findings = data.get("findings", result.findings) or []
            result.iocs = data.get("iocs", result.iocs) or []
            result.summary = data.get("summary", "")
            result.recommendation = data.get("recommendation", "")
        except (json.JSONDecodeError, ValueError):
            pass


# ------------------------------------------------------------------
# 风险评分模型
# ------------------------------------------------------------------

THREAT_WEIGHTS: dict[str, float] = {
    "c2": 0.9, "c2_server": 0.9, "c&c": 0.9,
    "malware": 0.8, "malware_distribution": 0.8,
    "phishing": 0.7, "phish": 0.7,
    "botnet": 0.8,
    "proxy": 0.4, "anonymizer": 0.4,
    "scanner": 0.5,
    "spam": 0.3,
    "suspicious": 0.3,
}

INFRA_TRUST: dict[str, float] = {
    "cloudflare": 0.3, "akamai": 0.3, "aws_waf": 0.3, "incapsula": 0.3,
    "amazon": 0.5, "aws": 0.5, "google": 0.5, "azure": 0.5, "microsoft": 0.5,
    "alibaba": 0.5, "tencent": 0.5, "huawei": 0.5,
}

RISK_LEVELS = ["低", "中", "高", "严重"]


def compute_risk_score(
    threat_labels: list[str],
    infra_org: str = "",
    behavioral_factors: list[str] | None = None,
) -> tuple[float, str]:
    """计算风险评分。

    Returns: (score 0.0-1.0, risk_level)
    """
    # 威胁标签权重
    max_threat = 0.0
    for label in threat_labels:
        key = label.lower().strip()
        for threat_key, weight in THREAT_WEIGHTS.items():
            if threat_key in key:
                max_threat = max(max_threat, weight)
                break

    if max_threat == 0.0:
        # 没有威胁标签，基础风险低
        return (0.1, "低")

    # 基础设施可信度
    infra_factor = 0.9  # 默认独立服务器
    org_lower = infra_org.lower()
    for infra_key, factor in INFRA_TRUST.items():
        if infra_key in org_lower:
            infra_factor = factor
            break

    # 行为模式系数
    behavior_factor = 1.0
    for factor in behavioral_factors or []:
        factor_lower = factor.lower()
        if "关联已知恶意" in factor_lower or "associated with" in factor_lower:
            behavior_factor *= 1.5
        elif "多源一致" in factor_lower or "multi-source" in factor_lower:
            behavior_factor *= 1.3
        elif "活跃" in factor_lower or "active" in factor_lower:
            behavior_factor *= 1.2

    score = min(max_threat * infra_factor * behavior_factor, 1.0)

    if score >= 0.8:
        level = "严重"
    elif score >= 0.5:
        level = "高"
    elif score >= 0.2:
        level = "中"
    else:
        level = "低"

    return (round(score, 3), level)
