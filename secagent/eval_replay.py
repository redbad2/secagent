"""评估回放支持（P1-1）：缓存工具返回而非最终结果。

设计要点：
- fixture 存"工具调用 → 返回"映射（从 SessionDB 存档的完整 messages 提取），
  入库到 tests/eval/fixtures/<target>.json，长期可复现（不受 ResultCache TTL 限制）。
- 回放时用 ReplayableMCP 替换 agent.mcp，查表返回工具结果；
  LLM 调用、信号提取、双轨评分全部走当前代码，因此 prompt/评分权重改动
  会直接反映在回放结果里（这是与旧 ResultCache 回放的本质区别）。
- 默认回放仍需真实 LLM；SECAGENT_EVAL_FAKE_LLM=1 时用 ScriptedLLM
  按 fixture 中的工具调用序列脚本化回放，做纯逻辑冒烟（离线、零成本）。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

logger = logging.getLogger(__name__)

# 回放未命中时的固定返回文本
REPLAY_MISS = "[replay miss] 该工具调用未在 fixture 中记录"

DEFAULT_FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "eval" / "fixtures"


def _canonical_args(args: Any) -> str:
    """把工具参数序列化为规范化 JSON（键排序），用作查表的 key。"""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, ValueError):
            return args
    try:
        return json.dumps(args, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(args)


def extract_tool_outputs(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """从存档会话的完整 messages 提取"工具调用 → 返回"的有序映射。

    Returns:
        [{"tool": full_name, "args": dict, "content": str}, ...]
        按会话中实际发生的顺序排列；内置工具（web_fetch/save_skill）也包含。
    """
    # tool_call_id -> (tool_name, args)
    call_index: dict[str, tuple[str, Any]] = {}
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") or {}
            name = fn.get("name", "")
            if name:
                call_index[tc.get("id", "")] = (name, fn.get("arguments", "{}"))

    outputs: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        name, raw_args = call_index.get(m.get("tool_call_id", ""), ("", "{}"))
        if not name:
            continue
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except (json.JSONDecodeError, ValueError):
            args = {"_raw": raw_args}
        outputs.append({
            "tool": name,
            "args": args if isinstance(args, dict) else {"_raw": args},
            "content": str(m.get("content", "")),
        })
    return outputs


def save_fixture(path: Path, target: str, target_type: str,
                 messages: list[dict[str, Any]]) -> int:
    """把会话中的工具返回写入 fixture 文件，返回记录条数。"""
    tool_calls = extract_tool_outputs(messages)
    fixture = {
        "target": target,
        "target_type": target_type,
        "tool_calls": tool_calls,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return len(tool_calls)


def load_fixture(fixtures_dir: Path, sample: dict[str, Any]) -> dict[str, Any] | None:
    """按样本的 fixture 字段（或默认 <target>.json）加载 fixture。"""
    target = sample["target"]
    filename = sample.get("fixture") or f"{target}.json"
    path = fixtures_dir / filename
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("fixture 解析失败 %s: %s", path, e)
        return None


class ReplayableMCP:
    """回放用 MCP 替身：接口与 MCPManager 对齐，从 fixture 查表返回工具结果。

    agent.analyze() 访问的接口面：
    - _sessions（dict，仅用 keys() 统计已连接 server）
    - failed_servers（property）
    - connected（property）
    - get_tool_definitions(server_filter, open_all_capabilities)
    - call_tool(full_name, args)
    - connect_all / disconnect_all（no-op）
    """

    def __init__(self, fixture: dict[str, Any]):
        self._fixture = fixture
        self._calls: list[dict[str, Any]] = fixture.get("tool_calls", [])
        # (tool, canonical_args) -> content
        self._table: dict[tuple[str, str], str] = {}
        for call in self._calls:
            self._table[(call["tool"], _canonical_args(call.get("args", {})))] = \
                str(call.get("content", ""))
        # 按工具名合成已连接 server 集合（agent 用 _sessions.keys() 统计覆盖度）
        servers = {c["tool"].split("__", 1)[0] for c in self._calls if "__" in c["tool"]}
        self._sessions: dict[str, Any] = {name: object() for name in servers}
        self.calls_made: list[tuple[str, str]] = []  # (tool, canonical_args)，供断言

    @property
    def connected(self) -> bool:
        return True

    @property
    def failed_servers(self) -> set[str]:
        return set()

    @property
    def tools(self) -> list[Any]:
        return list(self._calls)

    async def connect_all(self, server_names: set[str] | None = None) -> None:
        return None

    async def disconnect_all(self) -> None:
        return None

    def get_tool_definitions(self, server_filter: set[str] | None = None,
                             open_all_capabilities: bool = False) -> list[dict[str, Any]]:
        """按 fixture 中出现过的工具合成 OpenAI 格式的工具定义。

        参数 schema 从记录到的 args 键推导（宽松 object），帮助 LLM
        以相同参数形态发起调用，提高回放命中率。
        """
        # tool -> 见过的参数键集合
        arg_keys: dict[str, set[str]] = {}
        for call in self._calls:
            tool = call["tool"]
            if server_filter is not None and tool.split("__", 1)[0] not in server_filter:
                continue
            arg_keys.setdefault(tool, set()).update(
                (call.get("args") or {}).keys()
            )
        return [
            {
                "type": "function",
                "function": {
                    "name": tool,
                    "description": f"[replay] {tool}",
                    "parameters": {
                        "type": "object",
                        "properties": {k: {} for k in sorted(keys)},
                    },
                },
            }
            for tool, keys in sorted(arg_keys.items())
        ]

    async def call_tool(self, full_name: str, args: dict[str, Any]) -> str:
        """查表返回 fixture 中记录的工具结果；未命中返回固定文本。"""
        canonical = _canonical_args(args)
        self.calls_made.append((full_name, canonical))
        content = self._table.get((full_name, canonical))
        if content is None:
            logger.info("回放未命中: %s %s", full_name, canonical[:100])
            return REPLAY_MISS
        return content


# ====================================================================
# 脚本化假 LLM（SECAGENT_EVAL_FAKE_LLM=1）：离线纯逻辑冒烟
# ====================================================================

class _AsyncStream:
    """可异步迭代的 chunk 流（模拟 AsyncOpenAI 的流式响应）。"""

    def __init__(self, chunks: list[Any]):
        self._chunks = chunks

    def __aiter__(self):
        self._it = iter(self._chunks)
        return self

    async def __anext__(self):
        try:
            return next(self._it)
        except StopIteration:
            raise StopAsyncIteration


def _make_chunk(content: str | None = None,
                tool_call: tuple[str, str, dict] | None = None) -> Any:
    """构造一个流式 chunk。tool_call = (tc_id, name, args_dict)。"""
    tc_deltas = None
    if tool_call is not None:
        tc_id, name, args = tool_call
        tc_deltas = [SimpleNamespace(
            index=0, id=tc_id,
            function=SimpleNamespace(
                name=name,
                arguments=json.dumps(args, ensure_ascii=False),
            ),
        )]
    delta = SimpleNamespace(content=content, tool_calls=tc_deltas,
                            reasoning_content=None)
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)], usage=None)


class ScriptedAsyncLLM:
    """脚本化异步假 LLM：按 fixture 工具调用序列依次发起调用，随后输出结论。

    每次 create() 弹出序列中的下一个工具调用；序列耗尽（或收到
    response_format=json_object 的结构化补全请求）时返回结论 JSON。
    """

    def __init__(self, tool_calls: list[dict[str, Any]], conclusion: str | None = None):
        self._queue = [
            (c["tool"], c.get("args", {})) for c in tool_calls if "__" in c.get("tool", "")
        ]
        self._conclusion = conclusion or json.dumps({
            "risk_level": "中", "confidence": 0.5,
            "findings": ["回放分析（脚本化 LLM）"],
            "iocs": [], "summary": "回放冒烟结论", "recommendation": "以独立评分为准",
        }, ensure_ascii=False)
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._create)
        )

    async def _create(self, **kwargs: Any) -> _AsyncStream:
        if self._queue and not kwargs.get("response_format"):
            tool, args = self._queue.pop(0)
            tc_id = f"replay_tc_{len(self._queue)}"
            return _AsyncStream([_make_chunk(tool_call=(tc_id, tool, args))])
        return _AsyncStream([_make_chunk(content=self._conclusion)])

    async def close(self) -> None:
        return None


class ScriptedSyncLLM:
    """脚本化同步假 LLM：兜底辅助调用（记忆压缩/技能提取/结构化提取）。

    回显最后一条 user 消息内容，保证调用方拿到非空字符串且不产生网络请求。
    """

    def __init__(self):
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._create)
        )

    def _create(self, **kwargs: Any) -> Any:
        msgs = kwargs.get("messages") or []
        content = str(msgs[-1].get("content", "")) if msgs else ""
        if kwargs.get("response_format"):
            content = "{}"  # 结构化提取路径：返回空 JSON，走默认解析结果
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content[:2000]))]
        )
