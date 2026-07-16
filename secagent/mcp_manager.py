"""MCP 客户端管理：连接多个 MCP server，发现工具，统一调用。

关键设计：所有 MCP session 在同一个 async task 中创建和销毁，
避免 anyio "cancel scope in different task" 错误。
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from secagent.config import MCPServerConfig, redact_secrets

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

    def __init__(self, servers: dict[str, MCPServerConfig], tool_output_limit: int = 1500):
        self.servers_config = servers
        self._tool_output_limit = tool_output_limit
        self._sessions: dict[str, Any] = {}      # name -> ClientSession
        self._transports: dict[str, Any] = {}     # name -> transport ctx
        self._tools_cache: list[MCPTool] = []
        self._connected = False
        self._failed_servers: set[str] = set()    # 连接失败的 server 名
        # worker task 模式：每个连接由一个常驻 task 持有完整生命周期
        # anyio task group 要求 context manager 在同一 task enter/exit，
        # 故握手（__aenter__）与断开（__aexit__）必须落在同一 worker task，
        # 多个 worker 可并行完成握手以降低首屏延迟。
        self._conn_workers: dict[str, asyncio.Task] = {}
        self._stop_events: dict[str, asyncio.Event] = {}

    async def connect_all(self, server_names: set[str] | None = None) -> None:
        """连接 MCP server（并行握手）。可指定只连接子集。

        实现说明：每个 server 由一个常驻 worker task 持有连接的完整生命周期
        （enter context manager → 保持 → exit）。多个 worker 并行完成握手，
        显著降低多 server 场景的首屏延迟。worker 内的 anyio task group
        cancel scope 始终绑定在 worker task 自身，满足 same-task 约束。

        Args:
            server_names: 只连接这些 server。None = 连接全部。
        """
        loop = asyncio.get_event_loop()
        ready_futures: dict[str, asyncio.Future] = {}

        for name, conf in self.servers_config.items():
            if server_names is not None and name not in server_names:
                continue
            if not conf.url and not conf.command:
                logger.warning("MCP server %s 缺少 url 或 command，跳过", name)
                continue
            # 跳过已连接的（避免重复连接）
            if name in self._sessions or name in self._conn_workers:
                continue
            stop_event = asyncio.Event()
            self._stop_events[name] = stop_event
            ready_fut = loop.create_future()
            ready_futures[name] = ready_fut
            is_http = bool(conf.url and not conf.command)
            worker = asyncio.create_task(
                self._connection_worker(name, conf, is_http, ready_fut, stop_event)
            )
            self._conn_workers[name] = worker

        # 并行等待所有 worker 完成握手（就绪或失败）
        if ready_futures:
            await asyncio.gather(*ready_futures.values(), return_exceptions=True)

        # 并行发现工具
        await self._discover_tools()
        self._connected = True
        logger.info("MCP 连接完成: %d/%d 成功, 发现 %d 个工具",
                     len(self._sessions), len(self.servers_config),
                     len(self._tools_cache))

    async def _connection_worker(
        self,
        name: str,
        conf: MCPServerConfig,
        is_http: bool,
        ready_future: asyncio.Future,
        stop_event: asyncio.Event,
    ) -> None:
        """常驻 task：持有一个 MCP 连接的完整生命周期。

        握手阶段调用 _connect_http/_connect_stdio（内部 __aenter__ 启动 anyio
        task group，scope 绑定到本 worker task）。握手完成后阻塞等待
        stop_event，由 disconnect_all 触发后在同一 worker task 内 __aexit__，
        从根本上规避 anyio "cancel scope in different task" 错误。
        """
        try:
            if is_http:
                await self._connect_http(name, conf)
            else:
                await self._connect_stdio(name, conf)
            if not ready_future.done():
                ready_future.set_result(True)
        except Exception as e:
            self._failed_servers.add(name)
            logger.warning("MCP server %s 连接失败: %s", name, redact_secrets(str(e)))
            if not ready_future.done():
                ready_future.set_exception(e)
            return  # 握手失败，无 context 需清理，worker 直接退出

        # 保持 context manager 打开，等待 disconnect 信号
        try:
            await stop_event.wait()
        finally:
            # 在同一 worker task 内 exit（满足 anyio same-task 约束）
            await self._close_one(name)

    async def _close_one(self, name: str) -> None:
        """关闭单个连接的 session 与 transport（容忍清理阶段异常）。"""
        session = self._sessions.pop(name, None)
        transport = self._transports.pop(name, None)
        try:
            if session is not None:
                await session.__aexit__(None, None, None)
        except BaseException as e:
            logger.debug("关闭 session %s 时出错: %s", name, type(e).__name__)
        try:
            if transport is not None:
                await transport.__aexit__(None, None, None)
        except BaseException as e:
            # anyio task group 清理期的 CancelledError/RuntimeError 无害
            logger.debug("关闭 transport %s 时出错(可忽略): %s", name, type(e).__name__)

    async def _connect_http(self, name: str, conf: MCPServerConfig) -> None:
        """连接 Streamable HTTP MCP server。"""
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        headers = dict(conf.headers)
        headers.setdefault("Accept", "application/json, text/event-stream")
        # enter context manager and keep it alive
        ctx = streamablehttp_client(conf.url, headers=headers, timeout=conf.timeout)
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
        """从所有已连接 server 并行发现工具。

        list_tools 是普通 RPC 调用（不涉及 context manager 生命周期），
        跨 task 调用 session 安全，故用 gather 并行加速。
        """
        self._tools_cache = []
        items = list(self._sessions.items())  # snapshot，避免遍历期变动

        async def _discover_one(name: str, session: Any) -> list[MCPTool]:
            try:
                result = await asyncio.wait_for(session.list_tools(), timeout=15)
                return [
                    MCPTool(
                        server=name,
                        name=tool.name,
                        description=tool.description or "",
                        input_schema=tool.inputSchema or {"type": "object", "properties": {}},
                    )
                    for tool in result.tools
                ]
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception) as e:
                logger.warning("从 %s 发现工具失败（已跳过）: %s", name, type(e).__name__)
                self._failed_servers.add(name)
                return []

        batches = await asyncio.gather(*[_discover_one(n, s) for n, s in items])
        for tools in batches:
            self._tools_cache.extend(tools)

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def failed_servers(self) -> set[str]:
        """连接失败的 server 名称集合。"""
        return set(self._failed_servers)

    async def health_check(self) -> dict[str, dict[str, Any]]:
        """检查所有已连接 server 的健康状态。

        Returns:
            {server_name: {status, latency_ms, tools_count}}
            status: "ok" | "failed"
        """
        import time
        results: dict[str, dict[str, Any]] = {}

        # 已连接的 server
        for name, session in self._sessions.items():
            try:
                t0 = time.monotonic()
                result = await asyncio.wait_for(session.list_tools(), timeout=10)
                latency = round((time.monotonic() - t0) * 1000)
                results[name] = {
                    "status": "ok",
                    "latency_ms": latency,
                    "tools_count": len(result.tools),
                }
            except Exception as e:
                results[name] = {
                    "status": "failed",
                    "latency_ms": -1,
                    "tools_count": 0,
                    "error": str(e)[:100],
                }

        # 连接失败的 server
        for name in self._failed_servers:
            if name not in results:
                results[name] = {
                    "status": "disconnected",
                    "latency_ms": -1,
                    "tools_count": 0,
                }

        return results

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
        """从 MCP CallToolResult 提取文本内容，并做体积裁剪。

        提取纯文本后调用 prune_tool_output 做信号保留+结构感知裁剪，
        确保单条返回不超过 tool_output_limit 字符，同时保留
        compute_risk_score 所需的全部信号（与 extract_signals 对齐）。
        """
        if hasattr(result, "content"):
            parts = []
            for block in result.content:
                if hasattr(block, "text"):
                    parts.append(block.text)
                else:
                    parts.append(str(block))
            raw = "\n".join(parts)
        else:
            raw = str(result)
        return prune_tool_output(raw, self._tool_output_limit)

    async def disconnect_all(self) -> None:
        """关闭所有 MCP 连接。

        通过 stop_event 通知每个 worker task 自行 __aexit__（满足 anyio
        same-task 约束），并等待它们完成清理。对未走 worker 路径的残留
        连接（如旧代码遗留）做兜底同步关闭。
        """
        # 1. 通知所有 worker 退出（worker 自行 __aexit__）
        for event in self._stop_events.values():
            event.set()
        # 2. 等待所有 worker 完成清理
        if self._conn_workers:
            await asyncio.gather(*self._conn_workers.values(), return_exceptions=True)

        # 3. 兜底：清理 worker 未持有的残留连接（防御性）
        for name in list(self._sessions.keys()):
            await self._close_one(name)
        for name in list(self._transports.keys()):
            transport = self._transports.pop(name, None)
            if transport is not None:
                try:
                    await transport.__aexit__(None, None, None)
                except BaseException as e:
                    logger.debug("关闭残留 transport %s 时出错: %s", name, type(e).__name__)

        self._conn_workers.clear()
        self._stop_events.clear()
        self._tools_cache.clear()
        self._connected = False


# ====================================================================
# 工具返回裁剪：信号保留区 + 结构感知裁剪
# ====================================================================

def _format_signal_summary(signals: dict) -> str:
    """把提取出的信号格式化为简洁的保留区摘要。"""
    parts = []
    if signals.get("threat_labels"):
        parts.append("tag=" + ",".join(signals["threat_labels"]))
    if signals.get("domain_age_days") is not None:
        parts.append(f"age={signals['domain_age_days']}d")
    if signals.get("has_icp"):
        parts.append("icp=yes")
    if signals.get("infra_org"):
        parts.append(f"org={signals['infra_org']}")
    if signals.get("confidence", 0) > 0:
        parts.append(f"conf={signals['confidence']:.2f}")
    if signals.get("is_cdn_ip"):
        parts.append("cdn=yes")
    return " | ".join(parts) if parts else "无信号"


def _prune_json_array(text: str, limit: int) -> str:
    """裁剪 JSON 数组：保留前 5 条 + 统计摘要。"""
    import json
    try:
        data = json.loads(text.strip())
    except (json.JSONDecodeError, ValueError):
        return ""
    if not isinstance(data, list) or not data:
        return ""
    total = len(data)
    head = data[:5]
    summary = f"[共 {total} 条，展示前 {len(head)} 条]"
    return summary + "\n" + json.dumps(head, ensure_ascii=False, indent=1)[:limit]


def prune_tool_output(text: str, limit: int = 1500) -> str:
    """裁剪工具返回文本：信号保留区 + 结构感知裁剪 + 截断标记。

    保证 compute_risk_score 所需的信号不丢失（复用 extract_signals_from_text），
    同时把单条返回控制在 limit 字符以内。

    Args:
        text: MCP 工具返回的原始文本
        limit: 裁剪阈值（字符）

    Returns:
        裁剪后文本，格式：[信号保留区] + [截断标记] + [裁剪正文]
    """
    if not text or len(text) <= limit:
        return text

    from secagent.result_parser import extract_signals_from_text

    # 1. 提取信号作为保留区（与 compute_risk_score 对齐）
    signals = extract_signals_from_text(text)
    signal_summary = _format_signal_summary(signals)

    # 2. 结构感知裁剪正文
    body = ""
    stripped = text.strip()
    # JSON 数组形态：保留前 5 条 + 统计
    if stripped.startswith("[") and stripped.endswith("]"):
        pruned = _prune_json_array(stripped, limit - 500)
        body = pruned if pruned else text[:limit]
    # JSON 对象形态：尝试解析后保留关键字段
    elif stripped.startswith("{") and stripped.endswith("}"):
        try:
            import json
            data = json.loads(stripped)
            if isinstance(data, dict):
                # 按字段重要性保留，删除低价值字段
                _low_value = {"request_id", "api_version", "pagination",
                              "trace_id", "req_id", "request_time", "elapsed"}
                kept = {k: v for k, v in data.items() if k.lower() not in _low_value}
                body = json.dumps(kept, ensure_ascii=False, indent=1)[:limit]
            else:
                body = text[:limit]
        except (json.JSONDecodeError, ValueError):
            body = text[:limit]
    else:
        # 纯文本/不可解析：头尾保留 + 中间省略
        head_len = min(500, limit // 3)
        tail_len = min(500, limit // 3)
        if len(text) > head_len + tail_len:
            body = (text[:head_len]
                    + f"\n...(已省略 {len(text) - head_len - tail_len} 字符)...\n"
                    + text[-tail_len:])
        else:
            body = text[:limit]

    # 3. 拼接：信号保留区 + 截断标记 + 裁剪正文
    truncation_mark = f"[原始 {len(text)} 字符→裁剪为 {len(body)} 字符]"
    result = f"[关键信号: {signal_summary} | {truncation_mark}]\n{body}"

    # 最终保底：如果拼接后仍超限，再裁剪 body
    if len(result) > limit + 200:
        body = body[:limit - len(result) + len(body)]
        result = f"[关键信号: {signal_summary} | {truncation_mark}]\n{body}"

    return result
