"""测试工具返回裁剪与历史滑窗。

覆盖：
1. extract_signals_from_text: 从单条文本提取信号
2. extract_signals: 多条消息合并（与重构前行为一致）
3. prune_tool_output: 裁剪逻辑（信号保留+结构感知+截断标记）
4. _maybe_slide_window: 滑窗降级（早期 tool 消息压缩为信号摘要）
"""

import json

from secagent.result_parser import (
    extract_signals, extract_signals_from_text,
)
from secagent.mcp_manager import prune_tool_output


# ====================================================================
# extract_signals_from_text
# ====================================================================

class TestExtractSignalsFromText:
    def test_empty(self):
        sig = extract_signals_from_text("")
        assert sig["threat_labels"] == []
        assert sig["domain_age_days"] is None
        assert sig["has_icp"] is False
        assert sig["infra_org"] == ""
        assert sig["confidence"] == 0.0
        assert sig["is_cdn_ip"] is False

    def test_ctia_threat_tags(self):
        text = '{"tag": "c2", "confidence": 0.95, "classification": "malware"}'
        sig = extract_signals_from_text(text)
        assert "c2" in sig["threat_labels"]
        assert "malware" in sig["threat_labels"]
        assert sig["confidence"] == 0.95

    def test_tags_array(self):
        text = '{"tags": ["c2", "botnet", "malware"]}'
        sig = extract_signals_from_text(text)
        assert set(sig["threat_labels"]) == {"c2", "botnet", "malware"}

    def test_filters_risk_classes(self):
        text = '{"tag": "white", "classification": "unknown"}'
        sig = extract_signals_from_text(text)
        assert sig["threat_labels"] == []

    def test_domain_age(self):
        text = '{"creation_date": "2026-07-01"}'
        sig = extract_signals_from_text(text)
        assert sig["domain_age_days"] is not None
        assert sig["domain_age_days"] >= 0

    def test_icp(self):
        text = '备案信息: 京ICP备12345号'
        sig = extract_signals_from_text(text)
        assert sig["has_icp"] is True

    def test_no_icp(self):
        text = 'no icp record found'
        sig = extract_signals_from_text(text)
        assert sig["has_icp"] is False

    def test_infra_org(self):
        text = '{"org": "Cloudflare"}'
        sig = extract_signals_from_text(text)
        assert sig["infra_org"] == "Cloudflare"

    def test_cdn_detection(self):
        text = '该 IP 属于 Cloudflare CDN 网络'
        sig = extract_signals_from_text(text)
        assert sig["is_cdn_ip"] is True

    def test_confidence_0_100(self):
        text = '{"confidence": 85}'
        sig = extract_signals_from_text(text)
        assert sig["confidence"] == 0.85


# ====================================================================
# extract_signals (合并多条消息，与重构前行为一致)
# ====================================================================

class TestExtractSignalsMerged:
    def test_empty_messages(self):
        sig = extract_signals([])
        assert sig["threat_labels"] == []
        assert sig["domain_age_days"] is None

    def test_no_tool_messages(self):
        sig = extract_signals([
            {"role": "system", "content": "你是一个 agent"},
            {"role": "user", "content": "分析 baidu.com"},
        ])
        assert sig["threat_labels"] == []

    def test_merge_labels_across_messages(self):
        msgs = [
            {"role": "tool", "content": '{"tag": "c2"}'},
            {"role": "tool", "content": '{"tag": "malware"}'},
        ]
        sig = extract_signals(msgs)
        assert set(sig["threat_labels"]) == {"c2", "malware"}

    def test_merge_dedup_labels(self):
        msgs = [
            {"role": "tool", "content": '{"tag": "c2"}'},
            {"role": "tool", "content": '{"tag": "C2"}'},  # 大小写不同
        ]
        sig = extract_signals(msgs)
        assert len(sig["threat_labels"]) == 1

    def test_merge_min_domain_age(self):
        msgs = [
            {"role": "tool", "content": '{"creation_date": "2020-01-01"}'},  # 老
            {"role": "tool", "content": '{"creation_date": "2026-07-10"}'},  # 新（更年轻）
        ]
        sig = extract_signals(msgs)
        # 取最小值（最年轻域名，风险最高）
        assert sig["domain_age_days"] is not None
        assert sig["domain_age_days"] < 20  # 7月10日注册，距今几天

    def test_merge_any_icp(self):
        msgs = [
            {"role": "tool", "content": "no icp"},
            {"role": "tool", "content": "京ICP备12345号"},
        ]
        sig = extract_signals(msgs)
        assert sig["has_icp"] is True

    def test_merge_first_infra_org(self):
        msgs = [
            {"role": "tool", "content": '{"org": "Cloudflare"}'},
            {"role": "tool", "content": '{"org": "Akamai"}'},
        ]
        sig = extract_signals(msgs)
        assert sig["infra_org"] == "Cloudflare"  # 取第一个非默认值


# ====================================================================
# prune_tool_output
# ====================================================================

class TestPruneToolOutput:
    def test_short_text_not_pruned(self):
        text = "short response"
        result = prune_tool_output(text, limit=1500)
        assert result == text  # 不超过阈值，原样返回

    def test_long_text_pruned_with_signal_header(self):
        text = '{"tag": "c2", "confidence": 0.95}' + ' "padding": "' + 'x' * 3000 + '"}'
        result = prune_tool_output(text, limit=1500)
        assert "[关键信号:" in result
        assert "tag=c2" in result
        assert "conf=0.95" in result
        assert len(result) < len(text)

    def test_signal_preserved_in_pruned(self):
        """裁剪后仍能从信号保留区提取到关键信号。"""
        text = '{"tag": "c2", "confidence": 0.95}' + ' "padding": "' + 'x' * 3000 + '"}'
        result = prune_tool_output(text, limit=1500)
        # 从裁剪后的文本仍能提取到信号
        sig = extract_signals_from_text(result)
        assert "c2" in sig["threat_labels"]
        assert sig["confidence"] == 0.95

    def test_json_array_pruned(self):
        items = [{"ip": f"1.2.3.{i}", "port": 80} for i in range(50)]
        text = json.dumps(items)
        result = prune_tool_output(text, limit=1500)
        assert "共 50 条" in result
        assert len(result) < len(text)

    def test_json_object_low_value_fields_removed(self):
        text = json.dumps({
            "tag": "c2",
            "request_id": "abc-123",
            "api_version": "v1",
            "confidence": 0.9,
            "padding": "x" * 3000,
        })
        result = prune_tool_output(text, limit=1500)
        assert "request_id" not in result
        assert "api_version" not in result

    def test_truncation_mark_present(self):
        text = "x" * 5000
        result = prune_tool_output(text, limit=1500)
        assert "原始 5000 字符" in result
        assert "裁剪" in result

    def test_plain_text_head_tail(self):
        text = "HEAD" + "x" * 3000 + "TAIL"
        result = prune_tool_output(text, limit=1500)
        assert "HEAD" in result
        assert "TAIL" in result
        assert "已省略" in result

    def test_empty_text(self):
        assert prune_tool_output("", limit=1500) == ""

    def test_signal_header_contains_all_signals(self):
        text = (
            '{"tag": "c2", "confidence": 0.95}'
            ' {"creation_date": "2026-07-01"}'
            ' 京ICP备12345号'
            ' {"org": "Cloudflare"}'
            + ' "padding": "' + 'x' * 3000 + '"}'
        )
        result = prune_tool_output(text, limit=1500)
        assert "tag=c2" in result
        assert "conf=0.95" in result
        assert "icp=yes" in result
        assert "cdn=yes" in result  # Cloudflare 触发 CDN 检测


# ====================================================================
# _maybe_slide_window
# ====================================================================

class TestSlideWindow:
    def _make_agent(self, tmp_home):
        from secagent.config import AgentConfig, LLMConfig
        from secagent.agent import SecurityAgent
        config = AgentConfig(
            llm=LLMConfig(base_url="http://localhost:9999/v1", api_key="test-key", model="test"),
            secagent_home=tmp_home,
            max_iterations=5,
            tool_output_limit=1500,
            window_rounds=3,
            window_trigger=12,
        )
        return SecurityAgent(config)

    def test_no_demotion_below_trigger(self, tmp_home):
        agent = self._make_agent(tmp_home)
        # 5 条 tool 消息 < trigger(12)，不应降级
        messages = [{"role": "system", "content": "sys"}]
        for i in range(5):
            messages.append({"role": "user", "content": f"q{i}"})
            messages.append({"role": "tool", "content": f'{{"tag": "c2"}} padding {i} ' + "x" * 100})
        agent._maybe_slide_window(messages)
        # 所有 tool 消息未被降级
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        assert all(not m["content"].startswith("[已降级") for m in tool_msgs)

    def test_demotion_above_trigger(self, tmp_home):
        agent = self._make_agent(tmp_home)
        # 20 条 tool 消息 > trigger(12)，应降级早期的
        messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            messages.append({"role": "assistant", "content": f"thinking {i}"})
            messages.append({"role": "tool", "content": f'{{"tag": "c2"}} padding {i} ' + "x" * 100})
        agent._maybe_slide_window(messages)
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        # 保留窗口 = keep_rounds*4 = 12，降级 = 20-12 = 8
        demoted = [m for m in tool_msgs if m["content"].startswith("[已降级")]
        intact = [m for m in tool_msgs if not m["content"].startswith("[已降级")]
        assert len(demoted) == 8
        assert len(intact) == 12

    def test_demoted_preserves_signals(self, tmp_home):
        agent = self._make_agent(tmp_home)
        messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            messages.append({"role": "assistant", "content": f"thinking {i}"})
            messages.append({"role": "tool", "content": f'{{"tag": "c2", "confidence": 0.9}} padding {i} ' + "x" * 100})
        agent._maybe_slide_window(messages)
        demoted = [m for m in messages if m["role"] == "tool" and m["content"].startswith("[已降级")]
        assert len(demoted) > 0
        # 降级后的内容仍包含信号
        assert "tag=c2" in demoted[0]["content"]
        assert "conf=0.90" in demoted[0]["content"]

    def test_no_double_demotion(self, tmp_home):
        agent = self._make_agent(tmp_home)
        messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            messages.append({"role": "assistant", "content": f"thinking {i}"})
            messages.append({"role": "tool", "content": f'{{"tag": "c2"}} padding {i} ' + "x" * 100})
        # 调用两次，第二次不应重复降级
        agent._maybe_slide_window(messages)
        agent._maybe_slide_window(messages)
        demoted = [m for m in messages if m["role"] == "tool" and m["content"].startswith("[已降级")]
        assert len(demoted) == 8  # 与第一次一致

    def test_assistant_messages_not_demoted(self, tmp_home):
        agent = self._make_agent(tmp_home)
        messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            messages.append({"role": "assistant", "content": f"assistant thinking {i} " + "x" * 100})
            messages.append({"role": "tool", "content": f'{{"tag": "c2"}} padding {i} ' + "x" * 100})
        agent._maybe_slide_window(messages)
        # assistant 消息不受影响
        assistant_msgs = [m for m in messages if m["role"] == "assistant"]
        assert all(not m["content"].startswith("[已降级") for m in assistant_msgs)
