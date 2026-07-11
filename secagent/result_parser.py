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
    evidence_chain: list[dict] = field(default_factory=list)
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
            "evidence_chain": self.evidence_chain,
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
    """校验 IPv4 和 IPv6 地址。"""
    import ipaddress
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def is_hash(target: str) -> bool:
    """检测是否为文件哈希（MD5/SHA1/SHA256）。"""
    t = target.strip().lower()
    if not all(c in "0123456789abcdef" for c in t):
        return False
    return len(t) in (32, 40, 64)


def is_cve(target: str) -> bool:
    """检测是否为 CVE ID（如 CVE-2024-1234）。"""
    import re
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', target.strip().upper()))


def detect_target_type(target: str) -> str:
    """自动检测输入类型。返回 'domain' | 'ip' | 'hash' | 'cve'。"""
    t = target.strip()
    if is_cve(t):
        return "cve"
    if is_hash(t):
        return "hash"
    if is_valid_ip(t):
        return "ip"
    return "domain"


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
            # findings 支持新旧两种格式
            raw_findings = data.get("findings", result.findings) or []
            if raw_findings and isinstance(raw_findings[0], dict):
                # 新格式：[{source, data, conclusion}]
                result.findings = [
                    f.get("conclusion", f.get("data", str(f)))
                    for f in raw_findings
                ]
            else:
                result.findings = raw_findings
            result.iocs = data.get("iocs", result.iocs) or []
            result.summary = data.get("summary", "")
            result.recommendation = data.get("recommendation", "")
            # evidence_chain 存入 raw_output 供后续分析
            if data.get("evidence_chain"):
                result.evidence_chain = data["evidence_chain"]
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
# 风险评分模型 v2：加权矩阵 + 上下文感知
# ------------------------------------------------------------------

# 威胁标签权重（0.0-1.0）
THREAT_WEIGHTS: dict[str, float] = {
    "c2": 0.95, "c2_server": 0.95, "c&c": 0.95,
    "malware": 0.85, "malware_distribution": 0.85, "trojan": 0.85,
    "phishing": 0.75, "phish": 0.75,
    "botnet": 0.80, "僵尸网络": 0.80,
    "exploit": 0.70, "漏洞利用": 0.70,
    "proxy": 0.35, "anonymizer": 0.35,
    "scanner": 0.45, "扫描": 0.45,
    "spam": 0.25, "垃圾邮件": 0.25,
    "suspicious": 0.30, "可疑": 0.30,
    "ddos": 0.50,
    "backdoor": 0.90, "后门": 0.90,
    "miner": 0.60, "挖矿": 0.60,
}

# 基础设施可信度（乘数，越低越可信）
INFRA_TRUST: dict[str, float] = {
    # CDN/WAF（显著降低风险）
    "cloudflare": 0.20, "akamai": 0.20, "aws_waf": 0.20,
    "incapsula": 0.20, "imperva": 0.20, "fastly": 0.20,
    "网宿": 0.25, "wswebcdn": 0.25,
    # 云服务商（适度降低）
    "amazon": 0.50, "aws": 0.50, "google": 0.50,
    "azure": 0.50, "microsoft": 0.50,
    "alibaba": 0.50, "aliyun": 0.50, "阿里云": 0.50,
    "tencent": 0.50, "腾讯云": 0.50,
    "huawei": 0.50, "华为云": 0.50,
    # 已知恶意 ASN（提高风险）
    "psychz": 1.3, "dacentec": 1.3, "hostinger": 1.2,
}

# 域名年龄加权（天数 -> 乘数）
AGE_FACTORS: list[tuple[int | float, float]] = [
    (7, 2.0),      # < 7天：风险 x2
    (30, 1.5),     # < 30天：风险 x1.5
    (90, 1.2),     # < 90天：风险 x1.2
    (365, 1.0),    # < 1年：正常
    (1825, 0.8),   # < 5年：降低
    (float("inf"), 0.6),  # > 5年：显著降低
]

RISK_LEVELS = ["低", "中", "高", "严重"]


def compute_risk_score(
    threat_labels: list[str],
    infra_org: str = "",
    behavioral_factors: list[str] | None = None,
    domain_age_days: int | None = None,
    has_icp: bool = False,
    confidence: float = 0.0,
) -> tuple[float, str]:
    """计算风险评分 v2：加权矩阵 + 上下文感知。

    Args:
        threat_labels: 威胁标签列表
        infra_org: 基础设施组织名
        behavioral_factors: 行为因素列表
        domain_age_days: 域名年龄（天数），None=未知
        has_icp: 是否有合法 ICP 备案
        confidence: 标签置信度（0-1），低置信度标签降权

    Returns: (score 0.0-1.0, risk_level)
    """
    # 1. 威胁标签权重（考虑置信度）
    max_threat = 0.0
    for label in threat_labels:
        key = label.lower().strip()
        for threat_key, weight in THREAT_WEIGHTS.items():
            if threat_key in key:
                # 低置信度标签降权
                adjusted = weight * max(confidence, 0.3) if confidence > 0 else weight
                max_threat = max(max_threat, adjusted)
                break

    if max_threat == 0.0:
        return (0.05, "低")

    # 2. 基础设施可信度
    infra_factor = 0.90  # 默认独立服务器
    org_lower = infra_org.lower()
    for infra_key, factor in INFRA_TRUST.items():
        if infra_key in org_lower:
            infra_factor = factor
            break

    # 3. 域名年龄加权
    age_factor = 1.0
    if domain_age_days is not None:
        for threshold, factor in AGE_FACTORS:
            if domain_age_days < threshold:
                age_factor = factor
                break

    # 4. ICP 备案（强安全信号）
    icp_factor = 0.7 if has_icp else 1.0

    # 5. 行为模式系数
    behavior_factor = 1.0
    for factor in behavioral_factors or []:
        fl = factor.lower()
        if "关联已知恶意" in fl or "associated with" in fl:
            behavior_factor *= 1.4
        elif "多源一致" in fl or "multi-source" in fl:
            behavior_factor *= 1.3
        elif "活跃" in fl or "active" in fl:
            behavior_factor *= 1.15
        elif "低置信度" in fl or "low confidence" in fl:
            behavior_factor *= 0.7

    # 综合评分
    score = min(max_threat * infra_factor * age_factor * icp_factor * behavior_factor, 1.0)

    if score >= 0.80:
        level = "严重"
    elif score >= 0.50:
        level = "高"
    elif score >= 0.20:
        level = "中"
    else:
        level = "低"

    return (round(score, 3), level)
