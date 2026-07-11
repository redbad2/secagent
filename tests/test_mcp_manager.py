"""测试 mcp_manager.py：纯函数部分可测。"""

import pytest
from secagent.mcp_manager import MCPTool, MCPManager
from secagent.config import MCPServerConfig


class TestMCPTool:
    def test_full_name(self):
        tool = MCPTool(name="test_tool", server="my_server", description="desc", input_schema={})
        assert tool.full_name == "my_server__test_tool"

    def test_full_name_with_prefix(self):
        tool = MCPTool(name="v1_exploit", server="ctia_exploit", description="", input_schema={})
        assert tool.full_name == "ctia_exploit__v1_exploit"


class TestMCPManagerGetToolDefinitions:
    def test_empty_servers(self):
        mgr = MCPManager({})
        assert mgr.get_tool_definitions() == []

    def test_format_conversion(self):
        """工具定义应转换为 OpenAI function calling 格式。"""
        mgr = MCPManager({})
        mgr._tools_cache = [
            MCPTool(
                name="query_domain",
                server="ctia_domain",
                description="查询域名情报",
                input_schema={
                    "type": "object",
                    "properties": {"domain": {"type": "string"}},
                    "required": ["domain"],
                },
            ),
        ]
        defs = mgr.get_tool_definitions()
        assert len(defs) == 1
        d = defs[0]
        assert d["type"] == "function"
        assert d["function"]["name"] == "ctia_domain__query_domain"
        assert "查询域名情报" in d["function"]["description"]
        assert "domain" in d["function"]["parameters"]["properties"]

    def test_server_filter(self):
        """server_filter 只返回指定 server 的工具。"""
        mgr = MCPManager({})
        mgr._tools_cache = [
            MCPTool(name="t1", server="ctia_domain", description="", input_schema={}),
            MCPTool(name="t2", server="ctia_ip", description="", input_schema={}),
            MCPTool(name="t3", server="hunter", description="", input_schema={}),
        ]
        defs = mgr.get_tool_definitions(server_filter={"ctia_domain", "ctia_ip"})
        names = [d["function"]["name"] for d in defs]
        assert "ctia_domain__t1" in names
        assert "ctia_ip__t2" in names
        assert "hunter__t3" not in names

    def test_no_server_filter_returns_all(self):
        mgr = MCPManager({})
        mgr._tools_cache = [
            MCPTool(name="t1", server="a", description="", input_schema={}),
            MCPTool(name="t2", server="b", description="", input_schema={}),
        ]
        assert len(mgr.get_tool_definitions()) == 2


class TestMCPManagerExtractContent:
    def test_extract_text_content(self):
        """从 mock CallToolResult 提取文本。"""
        mgr = MCPManager({})
        # 模拟 MCP CallToolResult 结构
        class MockContent:
            def __init__(self, text):
                self.type = "text"
                self.text = text
        class MockResult:
            content = [MockContent("hello world")]
        result = mgr._extract_content(MockResult())
        assert result == "hello world"

    def test_extract_multiple_contents(self):
        mgr = MCPManager({})
        class MockContent:
            def __init__(self, text):
                self.type = "text"
                self.text = text
        class MockResult:
            content = [MockContent("part1"), MockContent("part2")]
        result = mgr._extract_content(MockResult())
        assert "part1" in result
        assert "part2" in result

    def test_extract_non_text_returns_str(self):
        mgr = MCPManager({})
        class MockResult:
            content = [42]
        result = mgr._extract_content(MockResult())
        assert "42" in result

    def test_extract_string_passthrough(self):
        mgr = MCPManager({})
        result = mgr._extract_content("already a string")
        assert result == "already a string"

    def test_extract_exception_passthrough(self):
        mgr = MCPManager({})
        err = RuntimeError("test error")
        result = mgr._extract_content(err)
        assert "test error" in result


class TestMCPManagerProperties:
    def test_connected_default_false(self):
        mgr = MCPManager({})
        assert mgr.connected is False

    def test_failed_servers_default_empty(self):
        mgr = MCPManager({})
        assert mgr.failed_servers == set()

    def test_tools_default_empty(self):
        mgr = MCPManager({})
        assert mgr.tools == []
