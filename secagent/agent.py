"""核心分析循环：OpenAI SDK tool calling + MCP 工具执行。"""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace
from typing import Any, Callable

from openai import OpenAI

from secagent.config import (
    AgentConfig, DOMAIN_SERVERS, IP_SERVERS, HASH_SERVERS, CVE_SERVERS,
    CRITICAL_SERVERS, OPTIONAL_SERVERS, EXA_SERVER,
)
from secagent.learning import MemoryStore, SkillStore, SessionDB, LearningTrigger
from secagent.mcp_manager import MCPManager
from secagent.prompt_builder import build_system_prompt
from secagent.result_parser import AnalysisResult, is_valid_ip, detect_target_type, parse_analysis_result

logger = logging.getLogger(__name__)


class SecurityAgent:
    """安全分析 Agent 核心。"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.llm = OpenAI(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
        )
        self.mcp = MCPManager(config.mcp_servers)

        # LLM 辅助函数：用于记忆压缩和技能提取
        def _llm_chat(system_prompt: str, user_prompt: str) -> str:
            resp = self.llm.chat.completions.create(
                model=config.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=2048,
            )
            return resp.choices[0].message.content or ""

        def _llm_compress(content: str, limit: int) -> str:
            return _llm_chat(
                f"你是记忆压缩器。将以下记忆压缩到{limit}字符以内，"
                "保留关键信息，合并重复项，删除过时内容。直接输出压缩后的文本，不要解释。",
                content,
            )

        self.memory = MemoryStore(config.secagent_home, llm_compress_fn=_llm_compress)
        self.skills = SkillStore(
            config.secagent_home,
            builtin_dir=_find_builtin_skills(),
        )
        self.sessions = SessionDB(config.secagent_home)
        self.learning = LearningTrigger(
            skills=self.skills,
            memory=self.memory,
            llm_call=_llm_chat,
        )
        self._connected = False
        # 会话状态（支持多轮追问）
        self._session_active = False
        self._session_messages: list[dict[str, Any]] = []
        self._session_target: str = ""
        self._session_target_type: str = ""
        self._session_tools_used: list[str] = []
        self._session_tool_defs: list[dict[str, Any]] = []
        self._session_model: str = ""

    async def connect(self, target_type: str | None = None) -> None:
        """连接 MCP server。可按目标类型过滤。

        Args:
            target_type: "domain" / "ip" / "hash" / "cve" / None(全部)
        """
        if target_type == "domain":
            server_names = set(DOMAIN_SERVERS)
        elif target_type == "ip":
            server_names = set(IP_SERVERS)
        elif target_type == "hash":
            server_names = set(HASH_SERVERS)
        elif target_type == "cve":
            server_names = set(CVE_SERVERS)
        else:
            server_names = None  # 全部

        # Exa 搜索：开关控制
        if server_names is not None and self.config.exa_enabled:
            server_names = server_names | {EXA_SERVER}
        elif server_names is None and not self.config.exa_enabled:
            # 全部连接但排除 exa
            server_names = set(self.config.mcp_servers.keys()) - {EXA_SERVER}

        await self.mcp.connect_all(server_names=server_names)
        self._connected = True
        logger.info("Agent 就绪: %d 个 MCP 工具可用 (目标类型=%s)",
                     len(self.mcp.tools), target_type or "all")

        # 检查核心 server 是否连接失败
        failed_critical = self.mcp.failed_servers & CRITICAL_SERVERS
        if failed_critical:
            logger.warning("核心 MCP server 连接失败: %s，分析质量可能受影响",
                           ", ".join(failed_critical))

    async def disconnect(self) -> None:
        """断开 MCP 连接。不关闭 sessions DB（由 close() 负责）。"""
        # 抑制清理阶段的噪音日志（httpx ConnectTimeout 等）
        noisy_loggers = ["httpcore", "httpx", "mcp.client.streamable_http"]
        saved_levels = {}
        for name in noisy_loggers:
            lg = logging.getLogger(name)
            saved_levels[name] = lg.level
            lg.setLevel(logging.CRITICAL)
        try:
            await self.mcp.disconnect_all()
        except BaseException:
            pass  # anyio task group cleanup errors are harmless
        finally:
            for name, level in saved_levels.items():
                logging.getLogger(name).setLevel(level)
        self._session_active = False

    def close(self) -> None:
        """关闭 sessions DB。在程序退出时调用。"""
        try:
            self.sessions.close()
        except Exception:
            pass

    async def analyze(
        self,
        target: str,
        depth: str = "standard",
        on_tool_call: Callable[[str, dict], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
        on_learning: Callable[[list[str]], None] | None = None,
        interactive: bool = True,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> AnalysisResult:
        """分析域名或 IP。

        Args:
            target: 域名或 IP 地址
            depth: "quick" | "standard" | "deep"
            on_tool_call: 可选回调 (tool_name, args) -> None，用于 CLI 显示进度
            on_learning: 可选回调 (actions_list) -> None，用于 CLI 显示学习结果
            interactive: True=交互模式(可提示用户确认), False=批处理模式
            confirm_fn: 确认回调，返回 True 表示用户同意创建技能
        """
        if not self._connected:
            # 先判断目标类型，用于过滤连接的 MCP server
            _target_type = detect_target_type(target)
            await self.connect(target_type=_target_type)

        target_type = detect_target_type(target)

        # 加载相关技能
        relevant_skills = self.skills.find_relevant(target_type, target)

        # 构建系统提示
        system_prompt = build_system_prompt(
            target=target,
            target_type=target_type,
            depth=depth,
            memory=self.memory,
            skills=relevant_skills,
            web_fetch_enabled=self.config.web_fetch_enabled,
            exa_enabled=self.config.exa_enabled,
        )

        # 获取工具定义（按目标类型过滤，排除辅助 server）
        connected_servers = set(self.mcp._sessions.keys())
        # 排除辅助 server 的工具，减少 token 消耗
        core_servers = connected_servers - OPTIONAL_SERVERS
        tool_defs = self.mcp.get_tool_definitions(server_filter=core_servers)
        if not tool_defs:
            logger.warning("没有可用的 MCP 工具，LLM 将仅基于自身知识分析")

        # 内置 web_fetch 工具（可选）
        from secagent.web_fetch import WEB_FETCH_TOOL_DEF, BUILTIN_TOOLS
        if self.config.web_fetch_enabled:
            tool_defs = tool_defs + [WEB_FETCH_TOOL_DEF]
            logger.info("web_fetch 工具已启用")

        # 多模型路由：按深度选择模型
        selected_model = self.config.models.select(depth, self.config.llm.model)
        if selected_model != self.config.llm.model:
            logger.info("模型路由: %s 深度 -> %s", depth, selected_model)

        # Agent 循环
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"分析目标: {target}"},
        ]

        tools_used: list[str] = []
        final_output, msg = await self._run_loop(
            messages, tool_defs, selected_model, on_tool_call,
            on_thinking=on_thinking,
            extra_tools_used=tools_used,
        )

        # 解析结果
        result = parse_analysis_result(
            target=target,
            target_type=target_type,
            llm_output=final_output,
            tools_used=tools_used,
        )

        # 保存会话状态，支持后续追问
        self._session_active = True
        self._session_messages = messages
        self._session_target = target
        self._session_target_type = target_type
        self._session_tools_used = tools_used
        self._session_tool_defs = tool_defs
        self._session_model = selected_model

        # 存档会话
        try:
            self.sessions.save(
                target=target,
                target_type=target_type,
                summary=result.summary or final_output[:100],
                risk_level=result.risk_level,
                messages=messages,
            )
            logger.info("会话已存档: %s (风险=%s)", target, result.risk_level)
        except Exception as e:
            logger.warning("会话存档失败: %s", e)

        # 事后学习
        learning_actions = self._post_analyze_learning(
            target=target,
            target_type=target_type,
            result=result,
            messages=messages,
            tools_used=tools_used,
            interactive=interactive,
            confirm_fn=confirm_fn,
        )
        if learning_actions and on_learning:
            on_learning(learning_actions)

        return result

    async def ask(
        self,
        question: str,
        on_tool_call: Callable[[str, dict], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
    ) -> str:
        """在当前分析会话基础上追问。

        必须在 analyze() 之后调用。复用已连接的 MCP server 和对话历史。
        追问中调用的工具会追加到会话工具列表。

        Args:
            question: 用户的追问内容
            on_tool_call: 工具调用回调
            on_thinking: 思考过程回调

        Returns:
            LLM 的回复文本
        """
        if not self._session_active:
            raise RuntimeError("没有活跃的分析会话，请先执行 analyze()")

        # 注入上下文：让 LLM 始终知道当前分析目标
        context_msg = (
            f"[上下文：当前分析目标为 {self._session_target} "
            f"(类型: {self._session_target_type})。"
            f"请围绕该目标的安全分析回答追问。]"
        )
        self._session_messages.append(
            {"role": "user", "content": f"{context_msg}\n\n{question}"}
        )

        # 运行循环（复用已有 tool_defs 和 model）
        final_output, _ = await self._run_loop(
            self._session_messages,
            self._session_tool_defs,
            self._session_model,
            on_tool_call,
            on_thinking=on_thinking,
            extra_tools_used=self._session_tools_used,
        )

        return final_output

    async def end_session(
        self,
        on_learning: Callable[[list[str]], None] | None = None,
        interactive: bool = True,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> None:
        """结束当前分析会话：执行学习、存档、断开连接。"""
        if not self._session_active:
            return

        # 重新解析最终结果（包含追问后的最新信息）
        final_output = ""
        for msg in reversed(self._session_messages):
            if msg.get("role") == "assistant" and msg.get("content"):
                final_output = msg["content"]
                break

        result = parse_analysis_result(
            target=self._session_target,
            target_type=self._session_target_type,
            llm_output=final_output,
            tools_used=self._session_tools_used,
        )

        # 更新存档
        try:
            self.sessions.save(
                target=self._session_target,
                target_type=self._session_target_type,
                summary=result.summary or final_output[:100],
                risk_level=result.risk_level,
                messages=self._session_messages,
            )
        except Exception as e:
            logger.warning("会话存档失败: %s", e)

        # 事后学习
        learning_actions = self._post_analyze_learning(
            target=self._session_target,
            target_type=self._session_target_type,
            result=result,
            messages=self._session_messages,
            tools_used=self._session_tools_used,
            interactive=interactive,
            confirm_fn=confirm_fn,
        )
        if learning_actions and on_learning:
            on_learning(learning_actions)

        # 清理会话状态
        self._session_active = False
        self._session_messages = []
        self._session_tools_used = []

        # 断开连接
        await self.disconnect()

    async def _run_loop(
        self,
        messages: list[dict[str, Any]],
        tool_defs: list[dict[str, Any]],
        model: str,
        on_tool_call: Callable[[str, dict], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
        on_stream: Callable[[str], None] | None = None,
        extra_tools_used: list[str] | None = None,
    ) -> tuple[str, Any]:
        """执行 LLM tool-calling 循环。

        Args:
            messages: 对话消息列表（会被原地修改）
            tool_defs: 工具定义
            model: 使用的模型
            on_tool_call: 工具调用回调
            on_thinking: 思考过程回调
            on_stream: 流式输出回调（最终回复时逐块调用）
            extra_tools_used: 追加工具调用记录到这个列表

        Returns:
            (final_output, last_message)
        """
        from secagent.web_fetch import BUILTIN_TOOLS

        iteration = 0
        msg = None
        final_output = ""

        while iteration < self.config.max_iterations:
            iteration += 1
            logger.debug("Agent 循环 - 迭代 %d/%d", iteration, self.config.max_iterations)

            try:
                response = self.llm.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tool_defs if tool_defs else None,
                    temperature=self.config.llm.temperature,
                    max_tokens=self.config.llm.max_tokens,
                    stream=True,
                )
            except Exception as e:
                logger.error("LLM 调用失败 (迭代 %d): %s", iteration, e)
                final_output = f"LLM 调用失败: {e}"
                break

            # 流式读取完整响应
            content_buf = ""
            tool_calls_data: dict[int, dict] = {}  # index -> {id, name, arguments}
            reasoning_buf = ""

            for chunk in response:
                delta = chunk.choices[0].delta if chunk.choices else None
                if not delta:
                    continue

                # reasoning_content（DeepSeek Reasoner）
                rc = getattr(delta, "reasoning_content", None)
                if rc:
                    reasoning_buf += rc

                # 文本内容
                if delta.content:
                    content_buf += delta.content
                    if on_stream:
                        on_stream(delta.content)

                # 工具调用
                if delta.tool_calls:
                    for tc_delta in delta.tool_calls:
                        idx = tc_delta.index
                        if idx not in tool_calls_data:
                            tool_calls_data[idx] = {"id": "", "name": "", "arguments": ""}
                        if tc_delta.id:
                            tool_calls_data[idx]["id"] = tc_delta.id
                        if tc_delta.function:
                            if tc_delta.function.name:
                                tool_calls_data[idx]["name"] = tc_delta.function.name
                            if tc_delta.function.arguments:
                                tool_calls_data[idx]["arguments"] += tc_delta.function.arguments

            # 构造 msg 对象（兼容原有逻辑）
            msg = SimpleNamespace()
            msg.content = content_buf
            msg.reasoning_content = reasoning_buf or None
            msg.tool_calls = []
            if tool_calls_data:
                for idx in sorted(tool_calls_data.keys()):
                    d = tool_calls_data[idx]
                    tc = SimpleNamespace()
                    tc.id = d["id"]
                    tc.function = SimpleNamespace()
                    tc.function.name = d["name"]
                    tc.function.arguments = d["arguments"]
                    msg.tool_calls.append(tc)

            # 展示思考过程
            if on_thinking:
                if reasoning_buf:
                    on_thinking(reasoning_buf)
                elif content_buf and msg.tool_calls:
                    on_thinking(content_buf)

            # 将 assistant 消息加入历史
            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": content_buf,
            }
            if msg.tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            messages.append(assistant_msg)

            if not msg.tool_calls:
                final_output = content_buf
                break

            # 并行执行工具调用
            tool_tasks = []
            for tc in msg.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}

                if on_tool_call:
                    on_tool_call(tool_name, args)

                if extra_tools_used is not None:
                    extra_tools_used.append(tool_name)
                else:
                    # analyze 首轮：记录到局部 tools_used
                    pass

                if tool_name in BUILTIN_TOOLS:
                    # 注入配置参数到内置工具
                    extra_args = {}
                    if tool_name == "web_fetch__fetch":
                        extra_args["verify_ssl"] = self.config.web_fetch_verify_ssl
                    tool_tasks.append(BUILTIN_TOOLS[tool_name](**args, **extra_args))
                else:
                    tool_tasks.append(self._call_tool_with_retry(tool_name, args))

            results = await asyncio.gather(*tool_tasks, return_exceptions=True)

            for tc, result in zip(msg.tool_calls, results):
                if isinstance(result, Exception):
                    content = f"工具调用失败: {type(result).__name__}: {result}"
                    logger.warning("工具 %s 失败: %s", tc.function.name, result)
                else:
                    content = str(result) if not isinstance(result, str) else result

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })

        else:
            # 达到 max_iterations
            logger.warning("达到最大迭代次数 %d，强制结束", self.config.max_iterations)
            final_output = msg.content if msg and msg.content else "分析未完成（达到最大迭代次数）"

        return final_output, msg

    async def _call_tool_with_retry(self, tool_name: str, args: dict, max_retries: int = 2) -> Any:
        """调用 MCP 工具，失败时自动重试。"""
        last_error: Exception = RuntimeError("unreachable")
        for attempt in range(max_retries + 1):
            try:
                return await self.mcp.call_tool(tool_name, args)
            except Exception as e:
                last_error = e
                if attempt < max_retries:
                    logger.warning("工具 %s 调用失败 (尝试 %d/%d): %s",
                                   tool_name, attempt + 1, max_retries + 1, e)
                    await asyncio.sleep(1 * (attempt + 1))
        raise last_error

    def _post_analyze_learning(
        self,
        target: str,
        target_type: str,
        result: AnalysisResult,
        messages: list[dict[str, Any]],
        tools_used: list[str],
        interactive: bool = True,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> list[str]:
        """事后学习：评估是否创建技能、更新记忆。"""
        try:
            assessment = self.learning.assess(
                target=target,
                target_type=target_type,
                result=result,
                messages=messages,
                tools_used=tools_used,
                interactive=interactive,
            )

            actions = self.learning.apply(
                assessment,
                interactive=interactive,
                confirm_fn=confirm_fn,
            )

            if actions:
                logger.info("学习触发: %s", "; ".join(actions))

            return actions
        except Exception as e:
            logger.warning("事后学习失败: %s", e)
            return []

    def add_memory(self, fact: str) -> None:
        """手动添加记忆。"""
        self.memory.add(fact)

    def search_history(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """搜索历史会话。"""
        return self.sessions.search(query, limit=limit)


def _find_builtin_skills() -> Any:
    """查找包内置技能目录。优先查找包内，其次查找上级目录。"""
    from pathlib import Path
    # pip/pipx 安装后：skills 在包内
    pkg_dir = Path(__file__).parent / "skills"
    if pkg_dir.exists():
        return pkg_dir
    # 开发模式：skills 在项目根目录
    root_dir = Path(__file__).parent.parent / "skills"
    return root_dir if root_dir.exists() else None
