"""测试 secagent/eval_replay.py：fixture 提取/加载、ReplayableMCP、脚本化 LLM 回放。

P1-1 验收重点：回放走当前代码——修改 compute_risk_score 后重跑回放，
独立评分列随之变化。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from secagent.agent import SecurityAgent
from secagent.eval import run_eval
from secagent.eval_replay import (
    REPLAY_MISS, ReplayableMCP, ScriptedAsyncLLM,
    extract_tool_outputs, load_fixture, save_fixture,
)


def _sample_messages() -> list[dict]:
    """构造一段含两次工具调用的会话消息。"""
    return [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "分析目标: evil.com"},
        {
            "role": "assistant", "content": "",
            "tool_calls": [{
                "id": "tc_1", "type": "function",
                "function": {"name": "ctia_domain__query",
                             "arguments": '{"domain": "evil.com"}'},
            }],
        },
        {"role": "tool", "tool_call_id": "tc_1",
         "content": '{"data": {"tags": [{"tag_name": "c2", "confidence": 90}]}}'},
        {
            "role": "assistant", "content": "",
            "tool_calls": [{
                "id": "tc_2", "type": "function",
                "function": {"name": "qianxin_fdp_domain__whois",
                             "arguments": '{"domain": "evil.com"}'},
            }],
        },
        {"role": "tool", "tool_call_id": "tc_2",
         "content": '{"creation_date": "2026-07-01"}'},
        {"role": "assistant",
         "content": '{"risk_level": "高", "confidence": 0.9}'},
    ]


def _sample_fixture() -> dict:
    return {
        "target": "evil.com",
        "target_type": "domain",
        "tool_calls": extract_tool_outputs(_sample_messages()),
    }


class TestExtractToolOutputs:
    def test_extracts_calls_in_order(self):
        calls = extract_tool_outputs(_sample_messages())
        assert len(calls) == 2
        assert calls[0]["tool"] == "ctia_domain__query"
        assert calls[0]["args"] == {"domain": "evil.com"}
        assert "c2" in calls[0]["content"]
        assert calls[1]["tool"] == "qianxin_fdp_domain__whois"

    def test_ignores_orphan_tool_messages(self):
        msgs = [{"role": "tool", "tool_call_id": "nope", "content": "x"}]
        assert extract_tool_outputs(msgs) == []


class TestFixtureIO:
    def test_save_and_load_roundtrip(self, tmp_path):
        n = save_fixture(tmp_path / "evil.com.json", "evil.com", "domain",
                         _sample_messages())
        assert n == 2
        fixture = load_fixture(tmp_path, {"target": "evil.com"})
        assert fixture is not None
        assert fixture["target"] == "evil.com"
        assert len(fixture["tool_calls"]) == 2

    def test_load_missing_returns_none(self, tmp_path):
        assert load_fixture(tmp_path, {"target": "ghost.com"}) is None

    def test_load_via_fixture_field(self, tmp_path):
        save_fixture(tmp_path / "custom.json", "evil.com", "domain",
                     _sample_messages())
        fixture = load_fixture(tmp_path, {"target": "evil.com",
                                          "fixture": "custom.json"})
        assert fixture is not None


class TestReplayableMCP:
    def test_hit_returns_recorded_content(self):
        mcp = ReplayableMCP(_sample_fixture())
        import asyncio
        content = asyncio.run(mcp.call_tool("ctia_domain__query",
                                            {"domain": "evil.com"}))
        assert "c2" in content
        assert mcp.calls_made == [("ctia_domain__query",
                                   '{"domain": "evil.com"}')]

    def test_miss_returns_fixed_text(self):
        mcp = ReplayableMCP(_sample_fixture())
        import asyncio
        content = asyncio.run(mcp.call_tool("ctia_domain__query",
                                            {"domain": "other.com"}))
        assert content == REPLAY_MISS

    def test_tool_definitions_from_fixture(self):
        mcp = ReplayableMCP(_sample_fixture())
        defs = mcp.get_tool_definitions()
        names = {d["function"]["name"] for d in defs}
        assert names == {"ctia_domain__query", "qianxin_fdp_domain__whois"}
        # 参数 schema 从记录的 args 键推导
        props = defs[0]["function"]["parameters"]["properties"]
        assert "domain" in props
        # server_filter 生效
        defs_filtered = mcp.get_tool_definitions(server_filter={"ctia_domain"})
        assert len(defs_filtered) == 1

    def test_sessions_reflect_fixture_servers(self):
        mcp = ReplayableMCP(_sample_fixture())
        assert set(mcp._sessions.keys()) == {"ctia_domain", "qianxin_fdp_domain"}
        assert mcp.failed_servers == set()
        assert mcp.connected is True


class TestReplayEndToEnd:
    """回放全链路：fixture + 脚本化假 LLM 跑完整 analyze。"""

    def _write_dataset(self, tmp_path: Path) -> Path:
        ds = tmp_path / "dataset.yaml"
        ds.write_text(yaml.dump({
            "samples": [{
                "target": "evil.com",
                "expected_risk_level": ["高", "严重"],
                "category": "malicious",
            }]
        }), encoding="utf-8")
        return ds

    def _write_fixture(self, tmp_path: Path) -> Path:
        fixtures_dir = tmp_path / "fixtures"
        save_fixture(fixtures_dir / "evil.com.json", "evil.com", "domain",
                     _sample_messages())
        return fixtures_dir

    @pytest.mark.asyncio
    async def test_replay_runs_current_code(self, mock_config, tmp_path,
                                            monkeypatch):
        """fixture 回放：无 MCP 网络跑通，结论来自脚本化 LLM，独立评分来自当前代码。"""
        monkeypatch.setenv("SECAGENT_EVAL_FAKE_LLM", "1")
        agent = SecurityAgent(mock_config)
        try:
            report = await run_eval(
                agent, dataset_path=self._write_dataset(tmp_path),
                online=False, fixtures_dir=self._write_fixture(tmp_path),
            )
        finally:
            agent.close()
        assert report.skipped == 0
        assert report.total == 1
        sr = report.samples[0]
        # LLM 结论（脚本化）：默认 conclusion 为"中"
        assert sr.actual == "中"
        # 独立评分（当前代码）：c2 标签 weight 0.95 → 严重
        assert sr.actual_independent == "严重"
        assert "分歧" in sr.discrepancy

    @pytest.mark.asyncio
    async def test_replay_reflects_scoring_changes(self, mock_config, tmp_path,
                                                   monkeypatch):
        """验收：修改 compute_risk_score 后重跑回放，独立评分列随之变化。"""
        monkeypatch.setenv("SECAGENT_EVAL_FAKE_LLM", "1")
        fixtures_dir = self._write_fixture(tmp_path)
        ds = self._write_dataset(tmp_path)
        agent = SecurityAgent(mock_config)
        try:
            # 第一次：正常评分 → c2 → 严重
            r1 = await run_eval(agent, dataset_path=ds, online=False,
                                fixtures_dir=fixtures_dir)
            assert r1.samples[0].actual_independent == "严重"

            # 第二次：把评分函数替换为永远返回"低"，重跑回放
            monkeypatch.setattr("secagent.agent.compute_risk_score",
                                lambda **kwargs: (0.01, "低"))
            r2 = await run_eval(agent, dataset_path=ds, online=False,
                                fixtures_dir=fixtures_dir)
            assert r2.samples[0].actual_independent == "低"
        finally:
            agent.close()

    @pytest.mark.asyncio
    async def test_replay_restores_agent_state(self, mock_config, tmp_path,
                                               monkeypatch):
        """回放后 agent 的 mcp/llm/连接状态被恢复。"""
        monkeypatch.setenv("SECAGENT_EVAL_FAKE_LLM", "1")
        agent = SecurityAgent(mock_config)
        old_mcp = agent.mcp
        try:
            await run_eval(agent, dataset_path=self._write_dataset(tmp_path),
                           online=False, fixtures_dir=self._write_fixture(tmp_path))
            assert agent.mcp is old_mcp
            assert agent._connected is False
        finally:
            agent.close()
