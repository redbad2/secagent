"""CTIA server 解析器：威胁情报返回的结构化解析。

CTIA（奇安信威胁情报）返回通常含 tags/classification/confidence 等字段。
本 parser 先尝试 json.loads 按 schema 解析，失败回退 generic 正则。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from secagent.parsers.generic import default_signals, regex_fallback, _RISK_CLASSES


class CTIAParser:
    """CTIA 威胁情报返回解析器。"""

    def parse(self, text: str) -> dict[str, Any]:
        """解析 CTIA 返回文本。先结构化，失败回退正则。"""
        signals = self._parse_json(text)
        if signals is not None:
            return signals
        return regex_fallback(text)

    def _parse_json(self, text: str) -> dict[str, Any] | None:
        """尝试从 JSON 结构提取信号。返回 None 表示解析失败。"""
        stripped = text.strip()
        # CTIA 返回可能被 prune_tool_output 包裹，提取 JSON 部分
        if stripped.startswith("[关键信号") or stripped.startswith("[已降级"):
            return None  # 降级格式交给 generic
        # 尝试找到 JSON 对象/数组
        json_str = self._extract_json(stripped)
        if not json_str:
            return None
        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return None

        signals = default_signals()

        # CTIA 可能返回 {data: {...}} 或直接 {...}
        if isinstance(data, dict):
            obj = data.get("data", data) if isinstance(data.get("data"), dict) else data
            if not isinstance(obj, dict):
                return None

            # 威胁标签：tags 数组或 classification 字段
            threat_labels: list[str] = []
            tags = obj.get("tags") or obj.get("tag")
            if isinstance(tags, list):
                for t in tags:
                    if isinstance(t, str) and t.lower() not in _RISK_CLASSES:
                        threat_labels.append(t)
                    elif isinstance(t, dict):
                        # tag 可能是 {tag_name: "c2", confidence: 0.9}
                        name = t.get("tag_name") or t.get("name") or t.get("tag", "")
                        if isinstance(name, str) and name.lower() not in _RISK_CLASSES:
                            threat_labels.append(name)
            elif isinstance(tags, str) and tags.lower() not in _RISK_CLASSES:
                threat_labels.append(tags)

            classification = obj.get("classification", "")
            if isinstance(classification, str) and classification.lower() not in _RISK_CLASSES:
                threat_labels.append(classification)

            # 去重
            seen: set[str] = set()
            signals["threat_labels"] = [
                t for t in threat_labels if not (t.lower() in seen or seen.add(t.lower()))
            ]

            # 置信度
            conf = obj.get("confidence") or obj.get("threat_level_confidence", 0)
            if isinstance(conf, (int, float)):
                signals["confidence"] = conf / 100.0 if conf > 1.0 else float(conf)

            return signals

        return None

    def _extract_json(self, text: str) -> str | None:
        """从文本中提取最外层 JSON 对象或数组。"""
        for i, ch in enumerate(text):
            if ch in "{[":
                # 找匹配的闭合括号
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
