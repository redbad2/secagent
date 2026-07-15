"""测试 agent.py：核心分析循环（mock LLM + MCP）。"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from secagent.agent import SecurityAgent
from secagent.config import AgentConfig, LLMConfig, ModelRouter


@pytest.fixture
def mock_config(tmp_home):
    return AgentConfig(
        llm=LLMConfig(
            base_url="http://localhost:9999/v1",
            api_key="test-key",
            model="test-model",
        ),
        models=ModelRouter(fast="test-fast", standard="test-model", reasoning="test-reasoner"),
        mcp_servers={},
        max_iterations=5,
        timeout=10,
        secagent_home=tmp_home,
        web_fetch_enabled=False,
        exa_enabled=False,
    )


@pytest.fixture
def agent(mock_config):
    return SecurityAgent(mock_config)


def _make_stream_chunk(content=None, tool_calls=None, reasoning=None):
    """构造一个流式 chunk。"""
    delta = SimpleNamespace()
    delta.content = content
    delta.tool_calls = tool_calls
    delta.reasoning_content = reasoning
    choice = SimpleNamespace()
    choice.delta = delta
    chunk = SimpleNamespace()
    chunk.choices = [choice]
    return chunk


def _make_stream_tool_call_delta(index, tc_id=None, name=None, arguments=None):
    """构造流式工具调用 delta。"""
    tc = SimpleNamespace()
    tc.index = index
    tc.id = tc_id
    tc.function = SimpleNamespace()
    tc.function.name = name
    tc.function.arguments = arguments
    return tc


def _make_stream_response(content=None, tool_calls_deltas=None):
    """构造完整的流式响应（chunk 列表）。"""
    chunks = []
    if content:
        # 分成几个 chunk 模拟流式
        mid = len(content) // 2
        chunks.append(_make_stream_chunk(content=content[:mid]))
        chunks.append(_make_stream_chunk(content=content[mid:]))
    if tool_calls_deltas:
        chunks.extend(tool_calls_deltas)
    chunks.append(_make_stream_chunk())  # 结束 chunk
    return chunks


class TestSecurityAgent:
    def test_init(self, agent, mock_config):
        assert agent.config == mock_config
        assert not agent._connected
        assert not agent._session_active

    def test_session_state_defaults(self, agent):
        assert agent._session_messages == []
        assert agent._session_target == ""
        assert agent._session_tools_used == []

    def test_close(self, agent):
        agent.sessions = MagicMock()
        agent.close()
        agent.sessions.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_ask_without_session_raises(self, agent):
        with pytest.raises(RuntimeError, match="没有活跃的分析会话"):
            await agent.ask("test question")

    @pytest.mark.asyncio
    async def test_end_session_noop_when_inactive(self, agent):
        await agent.end_session()
        assert not agent._session_active

    @pytest.mark.asyncio
    async def test_run_loop_no_tools(self, agent):
        """LLM 直接返回文本（无工具调用）。"""
        agent.llm = MagicMock()
        agent.llm.chat.completions.create.return_value = _make_stream_response(
            content='{"risk_level": "低", "confidence": 0.9}'
        )
        messages = [{"role": "user", "content": "test"}]
        output, msg, _ = await agent._run_loop(messages, [], "test-model")
        assert "低" in output
        assert len(messages) == 2  # user + assistant

    @pytest.mark.asyncio
    async def test_run_loop_with_tool_calls(self, agent):
        """LLM 调用一次工具后返回结果。"""
        agent.llm = MagicMock()
        agent.mcp = MagicMock()
        agent.mcp.call_tool = AsyncMock(return_value="tool result data")

        # 第一轮：工具调用
        tc_delta = _make_stream_tool_call_delta(0, tc_id="tc_1", name="test_tool", arguments='{"arg": "val"}')
        stream1 = _make_stream_response(tool_calls_deltas=[
            _make_stream_chunk(tool_calls=[tc_delta])
        ])
        # 第二轮：最终回复
        stream2 = _make_stream_response(content="final answer")

        agent.llm.chat.completions.create.side_effect = [stream1, stream2]

        messages = [{"role": "user", "content": "test"}]
        tools = [{"type": "function", "function": {"name": "test_tool"}}]
        output, msg, _ = await agent._run_loop(messages, tools, "test-model")

        assert output == "final answer"
        assert agent.mcp.call_tool.call_count == 1
        # messages: user, assistant(tool_calls), tool, assistant(final)
        assert len(messages) == 4

    @pytest.mark.asyncio
    async def test_run_loop_max_iterations(self, agent):
        """达到最大迭代次数时强制结束。"""
        agent.config.max_iterations = 2
        agent.llm = MagicMock()
        agent.mcp = MagicMock()
        agent.mcp.call_tool = AsyncMock(return_value="result")

        tc_delta = _make_stream_tool_call_delta(0, tc_id="tc_1", name="tool", arguments="{}")
        # 每轮都返回工具调用
        stream = _make_stream_response(
            content="partial",
            tool_calls_deltas=[_make_stream_chunk(tool_calls=[tc_delta])]
        )
        agent.llm.chat.completions.create.return_value = stream

        messages = [{"role": "user", "content": "test"}]
        tools = [{"type": "function", "function": {"name": "tool"}}]
        output, msg, _ = await agent._run_loop(messages, tools, "test-model")

        assert "partial" in output or "未完成" in output
        assert agent.llm.chat.completions.create.call_count == 2

    @pytest.mark.asyncio
    async def test_run_loop_llm_error(self, agent):
        """LLM 调用失败时返回错误信息。"""
        agent.llm = MagicMock()
        agent.llm.chat.completions.create.side_effect = Exception("API error")

        messages = [{"role": "user", "content": "test"}]
        output, msg, _ = await agent._run_loop(messages, [], "test-model")

        assert "LLM 调用失败" in output
        assert "API error" in output

    @pytest.mark.asyncio
    async def test_run_loop_on_thinking_callback(self, agent):
        """on_thinking 回调在有 reasoning_content 时被调用。"""
        agent.llm = MagicMock()
        stream = [
            _make_stream_chunk(content="answer", reasoning="let me think..."),
            _make_stream_chunk(),
        ]
        agent.llm.chat.completions.create.return_value = stream

        thinking_calls = []
        messages = [{"role": "user", "content": "test"}]
        await agent._run_loop(
            messages, [], "test-model",
            on_thinking=lambda t: thinking_calls.append(t),
        )
        assert len(thinking_calls) == 1
        assert "let me think" in thinking_calls[0]

    @pytest.mark.asyncio
    async def test_run_loop_extra_tools_used(self, agent):
        """extra_tools_used 列表记录工具调用。"""
        agent.llm = MagicMock()
        agent.mcp = MagicMock()
        agent.mcp.call_tool = AsyncMock(return_value="result")

        tc_delta = _make_stream_tool_call_delta(0, tc_id="tc_1", name="tool1", arguments="{}")
        stream1 = _make_stream_response(tool_calls_deltas=[
            _make_stream_chunk(tool_calls=[tc_delta])
        ])
        stream2 = _make_stream_response(content="done")
        agent.llm.chat.completions.create.side_effect = [stream1, stream2]

        used = []
        messages = [{"role": "user", "content": "test"}]
        tools = [{"type": "function", "function": {"name": "tool1"}}]
        await agent._run_loop(messages, tools, "test-model", extra_tools_used=used)

        assert "tool1" in used

    @pytest.mark.asyncio
    async def test_run_loop_stream_callback(self, agent):
        """on_stream 回调在流式输出时被调用。"""
        agent.llm = MagicMock()
        agent.llm.chat.completions.create.return_value = _make_stream_response(
            content="hello world"
        )

        stream_chunks = []
        messages = [{"role": "user", "content": "test"}]
        await agent._run_loop(
            messages, [], "test-model",
            on_stream=lambda t: stream_chunks.append(t),
        )
        assert "".join(stream_chunks) == "hello world"
