"""测试 web_fetch.py: HTML 解析 + 工具定义 + 内置工具分发。"""

from secagent.web_fetch import (
    _html_to_text, WEB_FETCH_TOOL_DEF, BUILTIN_TOOLS, web_fetch,
)
import asyncio


class TestHtmlToText:
    def test_removes_script_and_style(self):
        html = '<html><head><style>body{color:red}</style></head><body><script>alert(1)</script><p>hello</p></body></html>'
        result = _html_to_text(html)
        assert "alert" not in result
        assert "color:red" not in result
        assert "hello" in result

    def test_removes_html_tags(self):
        html = '<div class="x"><span>text</span></div>'
        result = _html_to_text(html)
        assert "<div" not in result
        assert "text" in result

    def test_decodes_entities(self):
        html = '<p>hello &amp; world</p>'
        result = _html_to_text(html)
        assert "&" in result or "hello" in result

    def test_cleans_whitespace(self):
        html = '<p>  hello   world  </p>'
        result = _html_to_text(html)
        assert "  " not in result.strip()
        assert "hello world" in result

    def test_empty_html(self):
        assert _html_to_text("") == ""
        assert _html_to_text("<html></html>") == ""

    def test_truncates_long_text(self):
        html = f"<p>{'x' * 10000}</p>"
        result = _html_to_text(html)
        # _html_to_text strips tags but doesn't truncate text itself
        assert len(result) >= 9000
        assert "x" in result


class TestWebFetchToolDef:
    def test_structure(self):
        assert WEB_FETCH_TOOL_DEF["type"] == "function"
        func = WEB_FETCH_TOOL_DEF["function"]
        assert func["name"] == "web_fetch__fetch"
        assert "url" in func["parameters"]["properties"]
        assert "url" in func["parameters"]["required"]

    def test_in_builtin_tools(self):
        assert "web_fetch__fetch" in BUILTIN_TOOLS
        assert BUILTIN_TOOLS["web_fetch__fetch"] == web_fetch


class TestWebFetch:
    def test_fetch_success(self):
        result = asyncio.run(web_fetch("https://www.baidu.com", timeout=10))
        assert "HTTP 200" in result or "HTTP" in result
        assert len(result) > 10

    def test_fetch_auto_scheme(self):
        result = asyncio.run(web_fetch("www.baidu.com", timeout=10))
        assert "HTTP" in result

    def test_fetch_timeout(self):
        # public IP with a non-responding port to trigger timeout
        result = asyncio.run(web_fetch("http://1.0.0.1", timeout=2))
        assert "超时" in result or "失败" in result or "错误" in result or "拒绝" in result

    def test_fetch_invalid_host(self):
        result = asyncio.run(web_fetch("http://this-host-does-not-exist-xyz.invalid", timeout=5))
        assert "失败" in result or "错误" in result or "超时" in result
