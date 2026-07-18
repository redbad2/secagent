"""FDP server 解析器：基础数据返回的结构化解析。

FDP（奇安信基础数据平台）返回通常含 WHOIS 注册信息、ICP 备案、
PDNS 解析记录等。本 parser 先尝试 json.loads 按 schema 解析，
失败回退 generic 正则。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from secagent.parsers.generic import default_signals, regex_fallback


class FDPParser:
    """FDP 基础数据返回解析器。"""

    def parse(self, text: str) -> dict[str, Any]:
        """解析 FDP 返回文本。先结构化，失败回退正则。"""
        signals = self._parse_json(text)
        if signals is not None:
            return signals
        return regex_fallback(text)

    def _parse_json(self, text: str) -> dict[str, Any] | None:
        """尝试从 JSON 结构提取信号。返回 None 表示解析失败。"""
        stripped = text.strip()
        if stripped.startswith("[关键信号") or stripped.startswith("[已降级"):
            return None
        # FDP 返回常是数组 [{...}, {...}]
        json_str = self._extract_json(stripped)
        if not json_str:
            return None
        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return None

        signals = default_signals()

        # FDP 可能返回数组或对象
        records = data if isinstance(data, list) else [data]
        for record in records:
            if not isinstance(record, dict):
                continue

            # 域名注册时间
            if signals["domain_age_days"] is None:
                created = (record.get("creation_date") or record.get("created")
                           or record.get("registration_date") or record.get("注册时间"))
                if isinstance(created, str):
                    signals["domain_age_days"] = self._parse_age(created)

            # ICP 备案
            if not signals["has_icp"]:
                icp = (record.get("icp") or record.get("icp_license")
                       or record.get("icp_record") or record.get("备案号") or "")
                if isinstance(icp, str) and icp.strip():
                    signals["has_icp"] = True

            # 基础设施组织（FDP IP 归属）
            if not signals["infra_org"]:
                org = (record.get("asn_org") or record.get("organization")
                       or record.get("org") or record.get("org_name") or "")
                if isinstance(org, str) and org.strip():
                    signals["infra_org"] = org.strip()

        return signals

    def _parse_age(self, date_str: str) -> int | None:
        """从日期字符串解析域名年龄（天数）。"""
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S"):
            try:
                clean = date_str.replace("/", "-")[:10] if fmt.startswith("%Y-%m-%d") else date_str
                reg_date = datetime.strptime(clean[:len(fmt.replace("%", "0"))], fmt)
                return max((datetime.now() - reg_date).days, 0)
            except (ValueError, TypeError):
                continue
        # 试试只取前 10 个字符
        try:
            reg_date = datetime.strptime(date_str[:10], "%Y-%m-%d")
            return max((datetime.now() - reg_date).days, 0)
        except (ValueError, TypeError):
            return None

    def _extract_json(self, text: str) -> str | None:
        """从文本中提取最外层 JSON。"""
        for i, ch in enumerate(text):
            if ch in "{[":
                open_ch = ch
                close_ch = "}" if ch == "{" else "]"
                depth = 0
                in_str = False
                escape = False
                for j in range(i, len(text)):
                    c = text[j]
                    if escape:
                        escape = False
                        continue
                    if c == "\\":
                        escape = True
                        continue
                    if c == '"':
                        in_str = not in_str
                        continue
                    if in_str:
                        continue
                    if c == open_ch:
                        depth += 1
                    elif c == close_ch:
                        depth -= 1
                        if depth == 0:
                            return text[i:j + 1]
                break
        return None
