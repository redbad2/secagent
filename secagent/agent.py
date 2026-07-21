"""核心分析循环：OpenAI SDK tool calling + MCP 工具执行。"""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace
from typing import Any, Callable

from openai import OpenAI, AsyncOpenAI

from secagent.config import (
    AgentConfig, DOMAIN_SERVERS, IP_SERVERS, HASH_SERVERS, CVE_SERVERS,
    CRITICAL_SERVERS, OPTIONAL_SERVERS, EXA_SERVER, redact_secrets,
)
from secagent.learning import MemoryStore, SkillStore, SessionDB, LearningTrigger
from secagent.mcp_manager import MCPManager
from secagent.prompt_builder import build_system_prompt
from secagent.result_parser import (
    AnalysisResult, is_valid_ip, detect_target_type, parse_analysis_result,
    extract_signals, extract_signals_with_sources, compute_risk_score, RISK_LEVELS,
    validate_iocs,
)
from secagent.cache import ResultCache

logger = logging.getLogger(__name__)


class SecurityAgent:
    """安全分析 Agent 核心。"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.llm = OpenAI(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
        )
        # 异步客户端：_run_loop 的流式调用走它，避免同步调用阻塞事件循环
        # （server 并发 /batch、/monitor/run 场景下同步调用会把并发退化为串行）
        self.llm_async = AsyncOpenAI(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
        )
        self.mcp = MCPManager(config.mcp_servers, tool_output_limit=config.tool_output_limit)

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
        self.cache = ResultCache(config.secagent_home)
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
        self._session_max_iter: int = 10

        # 注入 save_skill 内置工具，让 LLM 可以在分析中保存技能
        import secagent.web_fetch as _wf
        agent_self = self

        async def _save_skill_wrapper(name: str, content: str, trigger: str = "") -> str:
            # LLM 自动创建的技能是持久化提示注入面：默认隔离禁用，人工审核后启用
            from secagent.learning import audit_skill_content
            mode = agent_self.config.skills_llm_create
            if mode == "off":
                return "[已拒绝] 当前配置禁止 LLM 自动创建技能（skills.llm_create=off）"
            try:
                hits = audit_skill_content(content)
                # 内容审计命中注入模式时，即使配置为 on 也强制隔离
                quarantine = (mode == "quarantine") or bool(hits)
                path = agent_self.save_user_skill(name, content, trigger,
                                                  quarantine=quarantine)
                msg = f"[保存成功] 技能已保存到: {path}"
                if quarantine:
                    msg += "（已保存为禁用待审核状态，需用户 /skills show 审查后 /skills enable 启用）"
                if hits:
                    msg += f" [安全提示] 内容审计命中: {', '.join(hits)}"
                    logger.warning("save_skill 内容审计命中: %s (%s)", ", ".join(hits), name)
                return msg
            except Exception as e:
                return f"[保存失败] {e}"

        _wf._save_skill_builtin = _save_skill_wrapper
        _wf.BUILTIN_TOOLS["save_skill"] = _wf._save_skill_builtin

    async def connect(self, target_type: str | None = None, depth: str = "standard") -> None:
        """连接 MCP server。可按目标类型过滤。

        Args:
            target_type: "domain" / "ip" / "hash" / "cve" / None(全部)
            depth: 分析深度。deep 额外连接辅助 server（OPTIONAL_SERVERS 中已配置的），
                   用于关联资产查询和多源交叉验证；quick/standard 只连核心 server
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

        # deep 深度：额外连接辅助 server（grep_app/context7/brave 等），用于关联资产和交叉验证
        # 只连接用户实际配置过的辅助 server，避免连接不存在的 server
        if depth == "deep" and server_names is not None:
            configured_optional = set(self.config.mcp_servers.keys()) & OPTIONAL_SERVERS
            if configured_optional:
                server_names = server_names | configured_optional
                logger.info("deep 深度：额外连接辅助 server: %s", ", ".join(configured_optional))

        await self.mcp.connect_all(server_names=server_names)
        self._connected = True
        logger.info("Agent 就绪: %d 个 MCP 工具可用 (目标类型=%s, 深度=%s)",
                     len(self.mcp.tools), target_type or "all", depth)

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
        # 关闭 AsyncOpenAI 的 httpx 连接池，避免 serve 长期运行泄漏连接。
        # 兼容测试 mock：close 可能不存在或返回非 awaitable，需分别判断。
        try:
            closer = getattr(self.llm_async, "close", None)
            if closer is not None:
                maybe_coro = closer()
                if hasattr(maybe_coro, "__await__"):
                    await maybe_coro
        except Exception:
            pass
        self._session_active = False

    def close(self) -> None:
        """关闭持久化资源（sessions DB、缓存 DB）。在程序退出时调用。"""
        try:
            self.sessions.close()
        except Exception:
            pass
        try:
            self.cache.close()
        except Exception:
            pass

    async def analyze(
        self,
        target: str,
        depth: str = "standard",
        on_tool_call: Callable[[str, dict], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
        on_stream: Callable[[str], None] | None = None,
        on_learning: Callable[[list[str]], None] | None = None,
        interactive: bool = True,
        confirm_fn: Callable[[str], bool] | None = None,
        batch: bool = False,
        reuse: bool = False,
    ) -> AnalysisResult:
        """分析域名或 IP。

        Args:
            target: 域名或 IP 地址
            depth: "quick" | "standard" | "deep"
            on_tool_call: 可选回调 (tool_name, args) -> None，用于 CLI 显示进度
            on_thinking: 思考过程回调
            on_stream: 流式输出回调（最终回复时逐块调用）
            on_learning: 可选回调 (actions_list) -> None，用于 CLI 显示学习结果
            interactive: True=交互模式(可提示用户确认), False=批处理模式
            confirm_fn: 确认回调，返回 True 表示用户同意创建技能
            batch: True=批量模式，跳过 session 状态写入（并发安全）
            reuse: True=优先使用结果缓存，命中且未过期时跳过 LLM 与 MCP 调用
        """
        # 结果缓存：命中时直接返回，跳过连接与 LLM 循环（省 token、省时间）
        if reuse and self.cache is not None:
            cached = self.cache.get(target, depth)
            if cached is not None:
                result = AnalysisResult.from_dict(cached)
                result.from_cache = True
                logger.info("命中结果缓存: %s (depth=%s)", target, depth)
                return result

        if not self._connected:
            # 先判断目标类型，用于过滤连接的 MCP server
            _target_type = detect_target_type(target)
            await self.connect(target_type=_target_type, depth=depth)

        target_type = detect_target_type(target)

        # 加载相关技能（deep 深度额外加载交叉验证技能）
        relevant_skills = self.skills.find_relevant(target_type, target, depth=depth)

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

        # 获取工具定义
        connected_servers = set(self.mcp._sessions.keys())
        # quick/standard 排除辅助 server 减少 token；deep 保留（已为交叉验证连接）
        if depth == "deep":
            tool_servers = connected_servers
        else:
            tool_servers = connected_servers - OPTIONAL_SERVERS
        tool_defs = self.mcp.get_tool_definitions(server_filter=tool_servers)
        if not tool_defs:
            logger.warning("没有可用的 MCP 工具，LLM 将仅基于自身知识分析")

        # 内置 web_fetch 工具（可选）
        from secagent.web_fetch import WEB_FETCH_TOOL_DEF, SAVE_SKILL_TOOL_DEF, BUILTIN_TOOLS
        if self.config.web_fetch_enabled:
            tool_defs = tool_defs + [WEB_FETCH_TOOL_DEF]
            logger.info("web_fetch 工具已启用")
        # save_skill 内置工具（始终可用）
        tool_defs = tool_defs + [SAVE_SKILL_TOOL_DEF]

        # 多模型路由：按深度选择模型
        selected_model = self.config.models.select(depth, self.config.llm.model)
        if selected_model != self.config.llm.model:
            logger.info("模型路由: %s 深度 -> %s", depth, selected_model)

        # 按深度计算本轮最大迭代数（实质约束，而非仅 prompt 文字）
        # quick 5 / standard 10 / deep 15，但不超过 config.max_iterations 上限
        depth_iter_map = {"quick": 5, "standard": 10, "deep": 15}
        effective_max_iter = min(depth_iter_map.get(depth, 10), self.config.max_iterations)

        # Agent 循环
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"分析目标: {target}"},
        ]

        tools_used: list[str] = []
        final_output, msg, token_usage = await self._run_loop(
            messages, tool_defs, selected_model, on_tool_call,
            on_thinking=on_thinking,
            on_stream=on_stream,
            extra_tools_used=tools_used,
            max_iterations=effective_max_iter,
        )

        # 解析结果（同步函数，fallback 路径会同步调 LLM，
        # 放 worker 线程执行，避免阻塞事件循环）
        result = await asyncio.to_thread(
            parse_analysis_result,
            target=target,
            target_type=target_type,
            llm_output=final_output,
            tools_used=tools_used,
            llm_client=self.llm,
            llm_model=self.config.models.fast,
        )
        result.token_usage = token_usage

        # 独立风险评分：从工具返回中提取信号（按 server 分发到 per-server parser），
        # 用 compute_risk_score 交叉验证 LLM 判断
        signals, signal_sources = extract_signals_with_sources(messages)
        ind_score, ind_level = compute_risk_score(
            threat_labels=signals["threat_labels"],
            infra_org=signals["infra_org"],
            domain_age_days=signals["domain_age_days"],
            has_icp=signals["has_icp"],
            confidence=signals["confidence"],
        )
        result.independent_risk_level = ind_level
        result.independent_score = ind_score

        # 数据源覆盖度（P2-1）：记录连接/失败的 server，关键 server 缺失时压低置信度
        connected_servers = list(self.mcp._sessions.keys())
        failed_servers = list(self.mcp.failed_servers)
        critical_failed = [s for s in failed_servers if s in CRITICAL_SERVERS]
        result.coverage = {
            "connected": connected_servers,
            "failed": failed_servers,
            "critical_failed": critical_failed,
            "sources_with_signal": signal_sources,
        }

        # 独立置信度：基于数据源数量 + 信号提取完整度
        distinct_servers = {t.split("__")[0] for t in tools_used if "__" in t}
        source_factor = min(len(distinct_servers) / 4.0, 1.0)  # 4 个数据源即满
        signal_fields = [signals["threat_labels"], signals["infra_org"],
                         signals["domain_age_days"] is not None, signals["has_icp"]]
        completeness = sum(1 for f in signal_fields if f) / 4.0
        result.independent_confidence = round((source_factor + completeness) / 2.0, 2)
        # 关键 server 缺失时置信度上限压到 0.5
        if critical_failed:
            result.independent_confidence = min(result.independent_confidence, 0.5)

        # 分歧标注（带信号来源）
        if ind_level and result.risk_level and result.risk_level != "未知":
            if ind_level == result.risk_level:
                source_tag = f" [来源: {', '.join(signal_sources)}]" if signal_sources else ""
                result.risk_discrepancy = f"一致{source_tag}"
            else:
                source_tag = f" [信号来源: {', '.join(signal_sources)}]" if signal_sources else ""
                result.risk_discrepancy = f"分歧: LLM={result.risk_level}, 独立={ind_level}{source_tag}"
        elif not signals["threat_labels"]:
            result.risk_discrepancy = "无信号（未提取到威胁标签）"

        # CDN/WAF 误报抑制：域名解析到 CDN 共享 IP，CTIA 可能因 IP 历史误报
        if signals.get("is_cdn_ip") and result.risk_level in ("高", "严重"):
            result.false_positive_warning = (
                "该域名解析到 CDN/WAF 共享 IP，CTIA 可能因该 IP 历史托管恶意而误报，"
                "建议结合域名本身行为和页面内容综合判断"
            )
            logger.info("误报抑制: 检测到 CDN/WAF 共享 IP，LLM 报 %s 可能误报", result.risk_level)

        # IOC 校验（P1-2）：验证 LLM 输出的 IOC 是否在工具返回中验证过
        if result.iocs:
            tool_texts = [str(m["content"]) for m in messages
                          if m.get("role") == "tool" and m.get("content")]
            verified, unverified = validate_iocs(result.iocs, tool_texts)
            result.verified_iocs = verified
            result.unverified_iocs = unverified

        logger.info("风险交叉验证: LLM=%s, 独立=%s(%.2f), 置信度=%.2f, %s",
                     result.risk_level, ind_level, ind_score,
                     result.independent_confidence, result.risk_discrepancy)

        # 保存会话状态（批量模式跳过，避免并发冲突）
        if not batch:
            self._session_active = True
            self._session_messages = messages
            self._session_target = target
            self._session_target_type = target_type
            self._session_tools_used = tools_used
            self._session_tool_defs = tool_defs
            self._session_model = selected_model
            self._session_max_iter = effective_max_iter

        # 存档会话（批量模式仍写入 DB，但不写实例状态）
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

        # 事后学习（批量模式跳过）。同步函数（内部可能同步调 LLM 提炼技能），
        # 放 worker 线程执行，避免阻塞事件循环
        learning_actions = []
        if not batch:
            learning_actions = await asyncio.to_thread(
                self._post_analyze_learning,
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

        # 写入结果缓存（成功的分析结果，供后续 --reuse 命中）
        if self.cache is not None:
            try:
                self.cache.put(target, depth, result.to_dict())
            except Exception as e:
                logger.warning("缓存写入失败: %s", e)

        return result

    async def ask(
        self,
        question: str,
        on_tool_call: Callable[[str, dict], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
        on_stream: Callable[[str], None] | None = None,
    ) -> str:
        """在当前分析会话基础上追问。

        必须在 analyze() 之后调用。复用已连接的 MCP server 和对话历史。
        追问中调用的工具会追加到会话工具列表。

        Args:
            question: 用户的追问内容
            on_tool_call: 工具调用回调
            on_thinking: 思考过程回调
            on_stream: 流式输出回调

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
        final_output, _, _ = await self._run_loop(
            self._session_messages,
            self._session_tool_defs,
            self._session_model,
            on_tool_call,
            on_thinking=on_thinking,
            on_stream=on_stream,
            extra_tools_used=self._session_tools_used,
            max_iterations=self._session_max_iter,
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

        result = await asyncio.to_thread(
            parse_analysis_result,
            target=self._session_target,
            target_type=self._session_target_type,
            llm_output=final_output,
            tools_used=self._session_tools_used,
            llm_client=self.llm,
            llm_model=self.config.models.fast,
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

        # 事后学习（同步函数，内部可能同步调 LLM，放 worker 线程执行）
        learning_actions = await asyncio.to_thread(
            self._post_analyze_learning,
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

    async def _stream_completion(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tool_defs: list[dict[str, Any]] | None,
        on_stream: Callable[[str], None] | None = None,
    ) -> tuple[str, str, list[dict[str, str]], dict]:
        """发起一次流式补全（异步客户端）并读取完整响应。

        Returns:
            (content, reasoning_content, tool_calls, usage)
            tool_calls: [{"id": str, "name": str, "arguments": str}]
            usage: {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int}
        """
        response = await self.llm_async.chat.completions.create(
            model=model,
            messages=messages,
            tools=tool_defs if tool_defs else None,
            temperature=self.config.llm.temperature,
            max_tokens=self.config.llm.max_tokens,
            stream=True,
            stream_options={"include_usage": True},
        )

        content_buf = ""
        reasoning_buf = ""
        tool_calls_data: dict[int, dict] = {}  # index -> {id, name, arguments}
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        async for chunk in response:
            # 流式 usage：最后一个 chunk（choices 为空）携带 usage
            chunk_usage = getattr(chunk, "usage", None)
            if chunk_usage:
                usage["prompt_tokens"] += getattr(chunk_usage, "prompt_tokens", 0) or 0
                usage["completion_tokens"] += getattr(chunk_usage, "completion_tokens", 0) or 0
                usage["total_tokens"] += getattr(chunk_usage, "total_tokens", 0) or 0

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

        tool_calls = [
            {"id": d["id"], "name": d["name"], "arguments": d["arguments"]}
            for d in (tool_calls_data[i] for i in sorted(tool_calls_data.keys()))
        ]
        return content_buf, reasoning_buf, tool_calls, usage

    async def _salvage_final_output(
        self,
        messages: list[dict[str, Any]],
        model: str,
        msg: Any,
        total_usage: dict,
        on_stream: Callable[[str], None] | None = None,
    ) -> str:
        """达到迭代上限时的兜底输出。

        若本轮已收集过工具数据，追加一条"禁止工具调用"的指令再发起一次
        补全（不计入迭代数），强制 LLM 基于已有信息输出最终结论；
        调用失败或无工具数据时，回退到最后一条 assistant 内容。
        """
        fallback = msg.content if msg and msg.content else "分析未完成（达到最大迭代次数）"
        has_tool_data = any(m.get("role") == "tool" for m in messages)
        if not has_tool_data:
            return fallback
        messages.append({
            "role": "user",
            "content": ("已达到工具调用上限。禁止再调用任何工具，"
                        "请立即基于已收集的信息，按既定 JSON 格式输出最终分析结论。"),
        })
        try:
            content, _reasoning, _tool_calls, usage = await self._stream_completion(
                model, messages, None, on_stream=on_stream,
            )
            for k in total_usage:
                total_usage[k] += usage[k]
            if content.strip():
                messages.append({"role": "assistant", "content": content})
                logger.info("salvage 成功：基于已有信息输出最终结论")
                return content
        except Exception as e:
            logger.warning("salvage 调用失败: %s", redact_secrets(str(e)))
        return fallback

    async def _run_loop(
        self,
        messages: list[dict[str, Any]],
        tool_defs: list[dict[str, Any]],
        model: str,
        on_tool_call: Callable[[str, dict], None] | None = None,
        on_thinking: Callable[[str], None] | None = None,
        on_stream: Callable[[str], None] | None = None,
        extra_tools_used: list[str] | None = None,
        max_iterations: int | None = None,
    ) -> tuple[str, Any, dict]:
        """执行 LLM tool-calling 循环。

        Args:
            messages: 对话消息列表（会被原地修改）
            tool_defs: 工具定义
            model: 使用的模型
            on_tool_call: 工具调用回调
            on_thinking: 思考过程回调
            on_stream: 流式输出回调（最终回复时逐块调用）
            extra_tools_used: 追加工具调用记录到这个列表
            max_iterations: 本轮循环的最大迭代数；None 则用 config 默认值

        Returns:
            (final_output, last_message, token_usage)
            token_usage: {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int}
        """
        from secagent.web_fetch import BUILTIN_TOOLS

        if max_iterations is None:
            max_iterations = self.config.max_iterations
        iteration = 0
        msg = None
        final_output = ""
        total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        while iteration < max_iterations:
            iteration += 1
            logger.debug("Agent 循环 - 迭代 %d/%d", iteration, max_iterations)

            try:
                content_buf, reasoning_buf, tool_calls, usage = await self._stream_completion(
                    model, messages, tool_defs, on_stream=on_stream,
                )
            except Exception as e:
                # LLM 调用失败：重试一次，然后降级到 fast 模型
                logger.warning("LLM 调用失败 (迭代 %d): %s，重试中...", iteration, redact_secrets(str(e)))
                try:
                    fallback_model = self.config.models.fast or model
                    content_buf, reasoning_buf, tool_calls, usage = await self._stream_completion(
                        fallback_model, messages, tool_defs, on_stream=on_stream,
                    )
                    logger.info("降级到模型 %s 成功", fallback_model)
                except Exception as e2:
                    _safe_err = redact_secrets(str(e2))
                    logger.error("LLM 调用重试失败 (迭代 %d): %s", iteration, _safe_err)
                    final_output = f"LLM 调用失败: {_safe_err}"
                    break

            for k in total_usage:
                total_usage[k] += usage[k]

            # 构造 msg 对象（兼容原有逻辑）
            msg = SimpleNamespace()
            msg.content = content_buf
            msg.reasoning_content = reasoning_buf or None
            msg.tool_calls = []
            for d in tool_calls:
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
                    # 用闭包包裹，捕获参数不匹配等调用期异常（LLM 可能不严格遵守 schema）
                    async def _safe_builtin(_fn=BUILTIN_TOOLS[tool_name], _args=args, _extra=extra_args):
                        try:
                            return await _fn(**_args, **_extra)
                        except TypeError as e:
                            return f"[工具调用参数错误] {e}"
                        except Exception as e:
                            return f"[工具调用失败] {type(e).__name__}: {e}"
                    tool_tasks.append(_safe_builtin())
                else:
                    tool_tasks.append(self._call_tool_with_retry(tool_name, args))

            results = await asyncio.gather(*tool_tasks, return_exceptions=True)

            for tc, result in zip(msg.tool_calls, results):
                # CancelledError 是 BaseException 子类，return_exceptions=True 不会捕获它，
                # 但若个别情况下漏到这里，也按失败处理而非取消整个分析
                if isinstance(result, BaseException) and not isinstance(result, Exception):
                    # CancelledError 等：工具被取消（如 MCP 超时），按失败处理
                    content = f"工具调用被取消: {type(result).__name__}"
                    logger.warning("工具 %s 被取消: %s", tc.function.name, result)
                elif isinstance(result, Exception):
                    content = f"工具调用失败: {type(result).__name__}: {result}"
                    logger.warning("工具 %s 失败: %s", tc.function.name, result)
                else:
                    content = str(result) if not isinstance(result, str) else result

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })

            # 历史滑窗：tool 消息数超过阈值时，对早期 tool 消息降级为信号保留区
            self._maybe_slide_window(messages)

        else:
            # 达到 max_iterations：兜底 salvage，禁止工具调用，
            # 强制 LLM 基于已收集信息输出最终结论，避免浪费已完成的工具调用
            logger.warning("达到最大迭代次数 %d，强制结束", max_iterations)
            final_output = await self._salvage_final_output(
                messages, model, msg, total_usage, on_stream=on_stream,
            )

        return final_output, msg, total_usage

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

    def _maybe_slide_window(self, messages: list[dict[str, Any]]) -> None:
        """历史滑窗：tool 消息数超过阈值时，对早期 tool 消息降级为信号保留区。

        保留最近 window_rounds 轮的 tool 消息完整，更早的 tool 消息
        content 替换为信号保留区（复用 extract_signals_from_text），
        防止 messages 随轮次线性膨胀。

        只降级 role=tool 的消息，不动 system/assistant 消息。
        """
        trigger = self.config.window_trigger
        keep_rounds = self.config.window_rounds

        # 统计 tool 消息数量
        tool_indices = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
        if len(tool_indices) <= trigger:
            return  # 未达阈值，不需要降级

        # 计算最近 keep_rounds*2 条 tool 消息的边界索引
        # （每轮最多调用多个工具，保守取 keep_rounds*4 作为保留窗口）
        keep_count = keep_rounds * 4
        if len(tool_indices) <= keep_count:
            return  # 保留窗口内全部，无需降级

        # 需要降级的 tool 消息索引（较早的）
        demote_indices = tool_indices[:-keep_count]

        from secagent.result_parser import extract_signals_from_text

        demoted = 0
        for idx in demote_indices:
            msg = messages[idx]
            content = msg.get("content", "")
            # 跳过已经是降级标记的（避免重复处理）
            if isinstance(content, str) and content.startswith("[已降级"):
                continue
            # 提取信号作为保留区
            signals = extract_signals_from_text(content)
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
            signal_str = " | ".join(parts) if parts else "无信号"
            orig_len = len(content)
            msg["content"] = f"[已降级 | 原始 {orig_len} 字符 | {signal_str}]"
            demoted += 1

        if demoted:
            logger.info("滑窗降级: %d 条 tool 消息已压缩为信号摘要", demoted)

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
        """公开接口：添加记忆。"""
        self.memory.add(fact)

    def search_history(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """公开接口：搜索历史。"""
        return self.sessions.search(query, limit=limit)

    def save_user_skill(self, name: str, content: str, trigger: str = "",
                        quarantine: bool = False) -> str:
        """保存用户技能（公共接口，供 CLI /save 和 LLM 工具使用）。

        Args:
            quarantine: True 时保存为禁用待审核状态（.disabled 标记），
                        需人工 enable 后才参与匹配。
        """
        if not trigger:
            trigger = "manual"
        path = self.skills.create_skill(name, content, trigger, quarantine=quarantine)
        return str(path)


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
