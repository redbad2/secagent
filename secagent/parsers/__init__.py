"""per-server 结构化解析层。

按 MCP server 名分发到对应 parser，每个 parser 先尝试按已知 schema
做 json.loads 结构化解析，失败回退 generic 正则 fallback。

分发入口：parse_server_output(server, text) -> dict[str, Any]
"""

from __future__ import annotations

from typing import Any

from secagent.parsers.generic import regex_fallback, default_signals
from secagent.parsers.ctia import CTIAParser
from secagent.parsers.fdp import FDPParser


# server 名 → parser 实例的映射
# 匹配规则：server 名包含关键词即匹配（如 "ctia_domain" 匹配 ctia）
_PARSERS: list[tuple[list[str], Any]] = [
    (["ctia"], CTIAParser()),
    (["fdp", "qianxin_fdp"], FDPParser()),
]


def parse_server_output(server: str, text: str) -> dict[str, Any]:
    """按 server 名分发到对应 parser 解析工具返回文本。

    Args:
        server: MCP server 名（如 "ctia_domain"、"qianxin_fdp_ip"）
        text: 工具返回的文本（经 _extract_content 拍平）

    Returns:
        信号 dict，结构与 extract_signals_from_text 一致
    """
    server_lower = server.lower()
    for keywords, parser in _PARSERS:
        if any(kw in server_lower for kw in keywords):
            return parser.parse(text)
    # 未知 server：走通用正则
    return regex_fallback(text)
