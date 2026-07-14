"""内置 web_fetch 工具：让 LLM 能访问目标 URL 的页面内容。

不依赖浏览器，用 httpx 抓取 HTML 然后提取文本。
config.yaml 中 web_fetch.enabled: true 开启，verify_ssl: false 允许自签证书。
"""

from __future__ import annotations

import re
import socket
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# OpenAI tool calling 格式的工具定义
WEB_FETCH_TOOL_DEF = {
    "type": "function",
    "function": {
        "name": "web_fetch__fetch",
        "description": (
            "抓取指定 URL 的网页内容并返回纯文本。"
            "用于安全分析时查看目标域名的实际 Web 内容（钓鱼页面、挂马站点等）。"
            "注意：只支持 HTTP/HTTPS，返回前 5000 字符的文本内容。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "要抓取的 URL，如 https://example.com",
                },
            },
            "required": ["url"],
        },
    },
}

# 简易 HTML -> 文本
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
_STYLE_RE = re.compile(r"<style[^>]*>.*?</style>", re.DOTALL | re.IGNORECASE)
_WS_RE = re.compile(r"\s+")


def _html_to_text(html: str) -> str:
    """简单 HTML 清理：去 script/style 标签，去 HTML 标签，压空白。"""
    html = _SCRIPT_RE.sub("", html)
    html = _STYLE_RE.sub("", html)
    # 去标签
    text = _TAG_RE.sub(" ", html)
    # 压缩空白
    text = _WS_RE.sub(" ", text).strip()
    return text


async def web_fetch(url: str, timeout: int = 15, verify_ssl: bool = False) -> str:
    """抓取 URL 并返回纯文本内容。

    Args:
        url: 要抓取的 URL
        timeout: 超时秒数
        verify_ssl: 是否验证 SSL 证书（False=允许自签证书，安全分析场景默认关闭）

    Returns:
        页面文本（最多 5000 字符），或错误信息。
    """
    # 补全 scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # SSRF 防护：检查目标是否为内网/保留地址
    if not _is_safe_url(url):
        return f"[拒绝] 目标地址为内网/保留地址: {httpx.URL(url).host}"

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            verify=verify_ssl,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; secagent/0.1; security-analysis)",
            },
        ) as client:
            resp = await client.get(url)
            content_type = resp.headers.get("content-type", "")

            # 检查响应大小，防止超大响应耗尽内存
            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > 1_000_000:
                return f"[拒绝] 响应体过大 ({int(content_length)} bytes > 1MB)"

            if "text" in content_type or "html" in content_type or "xml" in content_type:
                text = _html_to_text(resp.text)
            else:
                text = f"[非文本内容] Content-Type: {content_type}, 大小: {len(resp.content)} bytes"

            # 截断
            if len(text) > 5000:
                text = text[:5000] + "\n...[截断]"

            # 附加 HTTP 元信息
            meta = f"[HTTP {resp.status_code}] {resp.url}\n[Content-Type: {content_type}]\n[Redirected: {'是' if str(resp.url) != url else '否'}]\n\n"
            return meta + text

    except httpx.TimeoutException:
        return f"[超时] {url} (timeout={timeout}s)"
    except httpx.ConnectError as e:
        return f"[连接失败] {url}: {e}"
    except Exception as e:
        return f"[错误] {url}: {type(e).__name__}: {e}"


# 内置工具分发表
BUILTIN_TOOLS: dict[str, Any] = {
    "web_fetch__fetch": web_fetch,
}


# LLM 可调用的 save_skill 工具定义
SAVE_SKILL_TOOL_DEF = {
    "type": "function",
    "function": {
        "name": "save_skill",
        "description": (
            "将当前分析中发现的有价值的分析方法/模式保存为技能（SKILL.md），"
            "供后续分析复用。当你发现一个通用的分析模式、判断规则、或误报处理方法时调用此工具。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "技能名称，如 'cdn-domain-false-positive'",
                },
                "content": {
                    "type": "string",
                    "description": "技能内容（Markdown 格式），包含触发条件、分析步骤、判断规则",
                },
                "trigger": {
                    "type": "string",
                    "description": "触发关键词，逗号分隔，如 'domain,cdn,false-positive'",
                },
            },
            "required": ["name", "content", "trigger"],
        },
    },
}


async def _save_skill_builtin(name: str, content: str, trigger: str) -> str:
    """内置 save_skill 工具：需要外部注入 agent 实例才能工作。"""
    return f"[错误] save_skill 未初始化，请检查 agent 配置"


def _is_safe_url(url: str) -> bool:
    """检查 URL 目标是否为内网/保留地址（SSRF 防护）。"""
    import ipaddress
    try:
        host = httpx.URL(url).host
    except Exception:
        return False
    try:
        info = socket.getaddrinfo(host, None)
        for item in info:
            ip = ipaddress.ip_address(item[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
    except socket.gaierror:
        return True  # 无法解析则放行，后续 http 请求自然会失败
    return True
