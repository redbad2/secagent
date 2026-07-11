"""MCP 客户端管理：连接多个 MCP server，发现工具，统一调用。

关键设计：所有 MCP session 在同一个 async task 中创建和销毁，
避免 anyio "cancel scope in different task" 错误。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from secagent.config import MCPServerConfig

logger = logging.getLogger(__name__)


@dataclass
class MCPTool:
    """单个 MCP 工具的元数据。"""
    server: str
    name: str
    description: str
    input_schema: dict[str, Any]

    @property
    def full_name(self) -> str:
        return f"{self.server}__{self.name}"


class MCPManager:
    """管理多个 MCP server 连接，提供统一工具接口。

    所有连接和断开操作在同一个 async task 中执行（不使用 gather），
    以满足 anyio task group 的 same-task 约束。
    """

    def __init__(self, servers: dict[str, MCPServerConfig]):
        self.servers_config = servers
        self._sessions: dict[str, Any] = {}      # name -> ClientSession
        self._transports: dict[str, Any] = {}     # name -> (read, write, extras)
        self._tools_cache: list[MCPTool] = []
        self._connected = False
        self._failed_servers: set[str] = set()    # 连接失败的 server 名

    async def connect_all(self, server_names: set[str] | None = None) -> None:
        """连接 MCP server。可指定只连接子集。

        Args:
            server_names: 只连接这些 server。None = 连接全部。
        """
        for name, conf in self.servers_config.items():
            if server_names is not None and name not in server_names:
                continue
            if conf.url and not conf.command:
                try:
                    await self._connect_http(name, conf)
                except Exception as e:
                    self._failed_servers.add(name)
                    logger.warning("MCP server %s 连接失败: %s", name, e)
            elif conf.command:
                try:
                    await self._connect_stdio(name, conf)
                except Exception as e:
                    self._failed_servers.add(name)
                    logger.warning("MCP server %s 连接失败: %s", name, e)
            else:
                logger.warning("MCP server %s 缺少 url 或 command，跳过", name)

        await self._discover_tools()
        self._connected = True
        logger.info("MCP 连接完成: %d/%d 成功, 发现 %d 个工具",
                     len(self._sessions), len(self.servers_config),
                     len(self._tools_cache))

    async def _connect_http(self, name: str, conf: MCPServerConfig) -> None:
        """连接 Streamable HTTP MCP server。"""
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        headers = dict(conf.headers)
        # enter context manager and keep it alive
        ctx = streamablehttp_client(conf.url, headers=headers)
        read, write, extras = await ctx.__aenter__()
        session = ClientSession(read, write)
        await session.__aenter__()
        await session.initialize()
        self._sessions[name] = session
        self._transports[name] = ctx
        logger.info("MCP server %s 已连接 (HTTP)", name)

    async def _connect_stdio(self, name: str, conf: MCPServerConfig) -> None:
        """连接 stdio MCP server。"""
        from mcp.client.stdio import stdio_client, StdioServerParameters
        from mcp import ClientSession

        params = StdioServerParameters(
            command=conf.command,
            args=conf.args,
            env={**conf.env} if conf.env else None,
        )
        ctx = stdio_client(params)
        read, write = await ctx.__aenter__()
        session = ClientSession(read, write)
        await session.__aenter__()
        await session.initialize()
        self._sessions[name] = session
        self._transports[name] = ctx
        logger.info("MCP server %s 已连接 (stdio)", name)

    async def _discover_tools(self) -> None:
        """从所有已连接 server 发现工具。"""
        self._tools_cache = []
        for name, session in self._sessions.items():
            try:
                result = await asyncio.wait_for(session.list_tools(), timeout=15)
                for tool in result.tools:
                    self._tools_cache.append(MCPTool(
                        server=name,
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.inputSchema or {"type": "object", "properties": {}},
                    ))
            except Exception as e:
                logger.warning("从 %s 发现工具失败: %s", name, e)

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def failed_servers(self) -> set[str]:
        """连接失败的 server 名称集合。"""
        return set(self._failed_servers)

    @property
    def tools(self) -> list[MCPTool]:
        return list(self._tools_cache)

    def get_tool_definitions(self, server_filter: set[str] | None = None) -> list[dict[str, Any]]:
        """返回 OpenAI tool calling 格式的工具定义。

        Args:
            server_filter: 只返回这些 server 的工具。None = 全部。
        """
        tools = self._tools_cache
        if server_filter is not None:
            tools = [t for t in tools if t.server in server_filter]
        return [
            {
                "type": "function",
                "function": {
                    "name": t.full_name,
                    "description": f"[{t.server}] {t.description}",
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

    async def call_tool(self, full_name: str, args: dict[str, Any]) -> Any:
        """调用 MCP 工具。full_name 格式: server__tool_name。"""
        if "__" not in full_name:
            raise ValueError(f"工具名格式错误（期望 server__tool）: {full_name}")

        server_name, tool_name = full_name.split("__", 1)
        session = self._sessions.get(server_name)
        if session is None:
            raise RuntimeError(f"MCP server {server_name} 未连接")

        timeout = 120
        if server_name in self.servers_config:
            timeout = self.servers_config[server_name].timeout

        result = await asyncio.wait_for(
            session.call_tool(tool_name, args),
            timeout=timeout,
        )
        return self._extract_content(result)

    def _extract_content(self, result: Any) -> str:
        """从 MCP CallToolResult 提取文本内容。"""
        if hasattr(result, "content"):
            parts = []
            for block in result.content:
                if hasattr(block, "text"):
                    parts.append(block.text)
                else:
                    parts.append(str(block))
            return "\n".join(parts)
        return str(result)

    async def disconnect_all(self) -> None:
        """关闭所有 MCP 连接（容忍 anyio task group 清理错误）。"""
        for name, session in list(self._sessions.items()):
            try:
                await session.__aexit__(None, None, None)
            except BaseException as e:
                logger.debug("关闭 session %s 时出错: %s", name, type(e).__name__)

        for name, ctx in list(self._transports.items()):
            try:
                await ctx.__aexit__(None, None, None)
            except BaseException as e:
                # anyio task group cleanup may raise CancelledError/RuntimeError
                # this is harmless - the connection is already closed
                logger.debug("关闭 transport %s 时出错(可忽略): %s", name, type(e).__name__)

        self._sessions.clear()
        self._transports.clear()
        self._tools_cache.clear()
        self._connected = False
