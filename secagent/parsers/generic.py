"""通用 server 解析器：不依赖特定 server schema，用正则提取信号。

这是所有 per-server parser 的 fallback 基座，也是未知 server 的默认解析器。
逻辑从 result_parser.py 的 extract_signals_from_text 抽出，保持完全一致。
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any


# 信号常量（与 result_parser.py 保持一致，避免循环导入）
_RISK_CLASSES = {"unknown", "white", "clean", "none", "black", "grey", "gray",
                 "malicious", "suspicious_low", "suspicious_high"}

_CDN_KEYWORDS = {"cloudflare", "akamai", "incapsula", "imperva", "fastly",
                 "aws_waf", "cloudfront", "azure cdn", "网宿", "wswebcdn",
                 "tencent cdn", "腾讯云CDN", "aliyun cdn"}

_DATE_PATTERNS = [
    r'(?:creation_date|created|registration_date|注册时间|创建时间)["\']?\s*[:=]\s*["\']?(\d{4}[-/]\d{2}[-/]\d{2})',
    r'"created"\s*:\s*"(\d{4}-\d{2}-\d{2})',
]

_ORG_PATTERNS = [
    r'(?:asn_org|organization|org|org_name|carrier|isp)["\']?\s*[:=]\s*["\']([^"\']{2,60})',
]

# 已知基础设施组织（用于子串匹配 fallback）
_INFRA_TRUST_KEYS = [
    "cloudflare", "akamai", "aws_waf", "incapsula", "imperva", "fastly",
    "网宿", "wswebcdn", "amazon", "aws", "google", "azure", "microsoft",
    "alibaba", "aliyun", "阿里云", "tencent", "腾讯云", "huawei", "华为云",
    "psychz", "dacentec", "hostinger",
]


def default_signals() -> dict[str, Any]:
    """返回信号集合的默认值。"""
    return {
        "threat_labels": [],
        "domain_age_days": None,
        "has_icp": False,
        "infra_org": "",
        "confidence": 0.0,
        "is_cdn_ip": False,
    }


def regex_fallback(text: str) -> dict[str, Any]:
    """用正则从文本中提取信号（通用 fallback 解析）。

    这是 extract_signals_from_text 的核心逻辑，保持与原实现完全一致。
    per-server parser 的结构化解析失败时回退到此函数。
    """
    if not text or not text.strip():
        return default_signals()

    signals = default_signals()

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
        text_lower = text.lower()
        for infra_key in _INFRA_TRUST_KEYS:
            if infra_key.lower() in text_lower:
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

    # 7. 降级格式 key=value 兼容解析（保留，不删除）
    if "[已降级" in text or "[关键信号" in text:
        if not threat_labels:
            m = re.search(r'tag=([^|\]]+)', text)
            if m:
                for v in m.group(1).strip().split(','):
                    v = v.strip()
                    if v and v.lower() not in _RISK_CLASSES:
                        threat_labels.append(v)
        if domain_age_days is None:
            m = re.search(r'age=(\d+)d', text)
            if m:
                try:
                    domain_age_days = int(m.group(1))
                except ValueError:
                    pass
        if not has_icp:
            has_icp = "icp=yes" in text_lower
        if not infra_org:
            m = re.search(r'org=([^|\]]+)', text)
            if m:
                infra_org = m.group(1).strip()
        if confidence == 0.0:
            m = re.search(r'conf=([0-9.]+)', text)
            if m:
                try:
                    confidence = float(m.group(1))
                except ValueError:
                    pass
        if not is_cdn_ip:
            is_cdn_ip = "cdn=yes" in text_lower

    signals["threat_labels"] = threat_labels
    signals["domain_age_days"] = domain_age_days
    signals["has_icp"] = has_icp
    signals["infra_org"] = infra_org
    signals["confidence"] = confidence
    signals["is_cdn_ip"] = is_cdn_ip
    return signals
