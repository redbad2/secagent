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
    # 独立风险评分（compute_risk_score 交叉验证）
    independent_risk_level: str = ""    # 独立计算的风险等级
    independent_score: float = 0.0      # 独立评分（0-1）
    independent_confidence: float = 0.0  # 独立置信度
    risk_discrepancy: str = ""          # 分歧描述
    token_usage: dict = field(default_factory=dict)  # LLM token 用量
    false_positive_warning: str = ""    # 误报警告（CDN/WAF 共享 IP 等）
    from_cache: bool = False            # 是否来自结果缓存（--reuse 命中）

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
            "raw_output": self.raw_output,
            "timestamp": self.timestamp,
            "independent_risk_level": self.independent_risk_level,
            "independent_score": self.independent_score,
            "independent_confidence": self.independent_confidence,
            "risk_discrepancy": self.risk_discrepancy,
            "token_usage": self.token_usage,
            "false_positive_warning": self.false_positive_warning,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AnalysisResult":
        """从 dict 反序列化为 AnalysisResult（to_dict 的逆操作）。

        缺失的字段用默认值，兼容旧版 dict（无独立评分字段时回退默认）。
        from_cache 不参与持久化（由调用方在命中时设置）。
        """
        return AnalysisResult(
            target=data.get("target", ""),
            target_type=data.get("target_type", ""),
            risk_level=data.get("risk_level", "未知"),
            confidence=data.get("confidence", 0.0),
            findings=data.get("findings", []),
            iocs=data.get("iocs", []),
            tools_used=data.get("tools_used", []),
            evidence_chain=data.get("evidence_chain", []),
            summary=data.get("summary", ""),
            recommendation=data.get("recommendation", ""),
            raw_output=data.get("raw_output", ""),
            timestamp=data.get("timestamp", ""),
            independent_risk_level=data.get("independent_risk_level", ""),
            independent_score=data.get("independent_score", 0.0),
            independent_confidence=data.get("independent_confidence", 0.0),
            risk_discrepancy=data.get("risk_discrepancy", ""),
            token_usage=data.get("token_usage", {}),
            false_positive_warning=data.get("false_positive_warning", ""),
            from_cache=True,
        )

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
    llm_client: Any = None,
    llm_model: str = "",
) -> AnalysisResult:
    """从 LLM 最终回复中提取结构化结果。

    提取策略（按优先级）：
    1. 正则匹配 markdown JSON 围栏 ```json...```
    2. 正则匹配裸 JSON（包含 risk_level 字段）
    3. LLM 结构化提取（最稳健，需要 llm_client）

    Args:
        llm_client: OpenAI 客户端（可选，用于结构化提取 fallback）
        llm_model: 使用的模型名
    """
    result = AnalysisResult(
        target=target,
        target_type=target_type,
        raw_output=llm_output,
        tools_used=tools_used,
    )

    # 尝试提取末尾的 JSON 块（用更宽松的正则）
    json_blocks = re.findall(r"```json\s*\n(.*?)\n\s*```", llm_output, re.DOTALL)
    if not json_blocks:
        # fallback: 找任何 {} 包裹的 JSON
        json_blocks = re.findall(r"\{[\s\S]*\"risk_level\"[\s\S]*\}", llm_output)
        if json_blocks:
            json_blocks = [json_blocks[-1]]  # 取最后一个
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

    # 兜底：如果没有 findings，尝试 LLM 结构化提取
    if (not result.findings or result.risk_level == "未知") and llm_client and llm_output.strip():
        try:
            structured = _llm_extract_result(llm_client, llm_model, llm_output)
            if structured:
                result.risk_level = structured.get("risk_level", result.risk_level)
                result.confidence = float(structured.get("confidence", result.confidence))
                result.summary = structured.get("summary", result.summary)
                result.recommendation = structured.get("recommendation", result.recommendation)
                if structured.get("findings"):
                    raw = structured["findings"]
                    result.findings = [f.get("conclusion", str(f)) if isinstance(f, dict) else str(f) for f in raw]
                if structured.get("iocs"):
                    result.iocs = structured["iocs"]
        except Exception:
            pass

    # 最终兜底：截断 LLM 输出作为 findings
    if not result.findings and llm_output:
        result.findings = [llm_output[:200] + "..." if len(llm_output) > 200 else llm_output]
        result.summary = result.summary or llm_output[:100]

    return result


def _llm_extract_result(llm_client: Any, model: str, text: str) -> dict[str, Any] | None:
    """用 LLM 的结构化输出从分析报告中提取 JSON。"""
    try:
        resp = llm_client.chat.completions.create(
            model=model,
            messages=[{
                "role": "user",
                "content": (
                    "从以下安全分析报告中提取 JSON 结果。只输出 JSON，不要其他内容。\n"
                    "JSON 格式：{risk_level, confidence, summary, recommendation, findings, iocs}\n\n"
                    f"{text[-8000:]}"  # 只取末尾 8000 字符
                ),
            }],
            temperature=0.0,
            max_tokens=1024,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content
        if content:
            return json.loads(content)
    except Exception:
        pass
    return None


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


# CTIA 整体风险分级（非具体标签），提取时应过滤
_RISK_CLASSES = {"unknown", "white", "clean", "none", "black", "grey", "gray",
                 "malicious", "suspicious_low", "suspicious_high"}

# CDN/WAF 关键词（误报抑制信号）
_CDN_KEYWORDS = {"cloudflare", "akamai", "incapsula", "imperva", "fastly",
                 "aws_waf", "cloudfront", "azure cdn", "网宿", "wswebcdn",
                 "tencent cdn", "腾讯云CDN", "aliyun cdn"}

# 域名注册时间匹配模式
_DATE_PATTERNS = [
    r'(?:creation_date|created|registration_date|注册时间|创建时间)["\']?\s*[:=]\s*["\']?(\d{4}[-/]\d{2}[-/]\d{2})',
    r'"created"\s*:\s*"(\d{4}-\d{2}-\d{2})',
]

# IP 归属组织匹配模式
_ORG_PATTERNS = [
    r'(?:asn_org|organization|org|org_name|carrier|isp)["\']?\s*[:=]\s*["\']([^"\']{2,60})',
]


def _default_signals() -> dict[str, Any]:
    """返回信号集合的默认值。"""
    return {
        "threat_labels": [],
        "domain_age_days": None,
        "has_icp": False,
        "infra_org": "",
        "confidence": 0.0,
        "is_cdn_ip": False,
    }


def extract_signals_from_text(text: str) -> dict[str, Any]:
    """从单条工具返回文本中提取风险评分所需信号（纯函数）。

    这是 extract_signals 的核心逻辑，抽成纯函数供裁剪模块复用：
    裁剪时先调用本函数提取信号作为"保留区"，再对原始文本截断，
    保证 compute_risk_score 的输入不会因裁剪而丢失。

    Args:
        text: 单条 MCP 工具返回的文本（经 _extract_content 拍平的纯文本）

    Returns:
        与 extract_signals 相同结构的 dict
    """
    if not text or not text.strip():
        return _default_signals()

    # 1. 威胁标签
    threat_labels: list[str] = []
    for m in re.finditer(r'"tags?"\s*:\s*\[([^\]]+)\]', text, re.IGNORECASE):
        for val_m in re.finditer(r'["\']([^"\']+)["\']', m.group(1)):
            val = val_m.group(1).strip()
            if val and val.lower() not in _RISK_CLASSES:
                threat_labels.append(val)
    for m in re.finditer(r'"tag"\s*:\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        val = m.group(1).strip()
        if val.lower() not in _RISK_CLASSES:
            threat_labels.append(val)
    for m in re.finditer(r'classification["\']?\s*[:=]\s*["\']([^"\']+)', text, re.IGNORECASE):
        val = m.group(1).strip()
        if val.lower() not in _RISK_CLASSES:
            threat_labels.append(val)
    seen: set[str] = set()
    threat_labels = [t for t in threat_labels if not (t.lower() in seen or seen.add(t.lower()))]

    # 2. 域名年龄
    domain_age_days = None
    for pat in _DATE_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                date_str = m.group(1).replace("/", "-")
                reg_date = datetime.strptime(date_str, "%Y-%m-%d")
                domain_age_days = max((datetime.now() - reg_date).days, 0)
                break
            except (ValueError, TypeError):
                pass

    # 3. ICP 备案
    has_icp = bool(re.search(r'[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁]?ICP备\d+', text))

    # 4. 基础设施组织
    infra_org = ""
    for pat in _ORG_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            infra_org = m.group(1).strip()
            break
    if not infra_org:
        for infra_key in INFRA_TRUST:
            if infra_key.lower() in text.lower():
                infra_org = infra_key
                break

    # 5. 标签置信度
    confidence = 0.0
    conf_match = re.search(r'"confidence["\']?\s*[:=]\s*([0-9.]+)', text, re.IGNORECASE)
    if conf_match:
        try:
            val = float(conf_match.group(1))
            confidence = val / 100.0 if val > 1.0 else val
        except (ValueError, TypeError):
            pass

    # 6. CDN/WAF 共享 IP 检测
    text_lower = text.lower()
    is_cdn_ip = any(kw in text_lower for kw in _CDN_KEYWORDS)

    return {
        "threat_labels": threat_labels,
        "domain_age_days": domain_age_days,
        "has_icp": has_icp,
        "infra_org": infra_org,
        "confidence": confidence,
        "is_cdn_ip": is_cdn_ip,
    }


def extract_signals(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """从 MCP 工具返回的文本中提取 compute_risk_score 所需的信号。

    遍历 messages 中所有 role=tool 的消息，对每条调用
    extract_signals_from_text 提取信号，再合并为统一结果。

    合并规则：
    - threat_labels: 列表合并去重保序
    - domain_age_days: 取最小值（最年轻的域名，风险最高）
    - has_icp / is_cdn_ip: 任一为真即为真
    - infra_org / confidence: 取第一个非默认值
    """
    tool_texts: list[str] = []
    for msg in messages:
        if msg.get("role") == "tool" and msg.get("content"):
            tool_texts.append(str(msg["content"]))

    if not tool_texts:
        return _default_signals()

    # 逐条提取，合并结果
    merged = _default_signals()
    all_labels: list[str] = []
    label_seen: set[str] = set()
    min_age = None

    for text in tool_texts:
        sig = extract_signals_from_text(text)

        # threat_labels: 合并去重保序
        for label in sig["threat_labels"]:
            if label.lower() not in label_seen:
                label_seen.add(label.lower())
                all_labels.append(label)

        # domain_age_days: 取最小值（最年轻域名风险最高）
        if sig["domain_age_days"] is not None:
            if min_age is None or sig["domain_age_days"] < min_age:
                min_age = sig["domain_age_days"]

        # has_icp / is_cdn_ip: 任一为真
        if sig["has_icp"]:
            merged["has_icp"] = True
        if sig["is_cdn_ip"]:
            merged["is_cdn_ip"] = True

        # infra_org / confidence: 取第一个非默认值
        if not merged["infra_org"] and sig["infra_org"]:
            merged["infra_org"] = sig["infra_org"]
        if merged["confidence"] == 0.0 and sig["confidence"] > 0.0:
            merged["confidence"] = sig["confidence"]

    merged["threat_labels"] = all_labels
    merged["domain_age_days"] = min_age
    return merged


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