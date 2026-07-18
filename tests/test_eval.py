"""测试 secagent/eval.py：数据集加载、命中判定、误报/漏报分类、报告汇总。"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from secagent.eval import (
    SampleResult, EvalReport, load_dataset, _is_hit, _classify_error,
    run_eval, save_baseline, compare_baseline, DEFAULT_DATASET,
)
from secagent.result_parser import AnalysisResult


class TestIsHit:
    def test_single_value_match(self):
        assert _is_hit("高", "高") is True

    def test_single_value_no_match(self):
        assert _is_hit("低", "高") is False

    def test_list_any_match(self):
        assert _is_hit("高", ["高", "严重"]) is True
        assert _is_hit("严重", ["高", "严重"]) is True

    def test_list_no_match(self):
        assert _is_hit("低", ["高", "严重"]) is False

    def test_unknown_not_hit(self):
        assert _is_hit("未知", "高") is False
        assert _is_hit("", "低") is False


class TestClassifyError:
    def test_benign_judged_malicious_is_fp(self):
        assert _classify_error("benign", "高") == "fp"
        assert _classify_error("benign", "中") == "fp"
        assert _classify_error("benign", "严重") == "fp"

    def test_benign_judged_low_no_error(self):
        assert _classify_error("benign", "低") == ""

    def test_malicious_judged_benign_is_fn(self):
        assert _classify_error("malicious", "低") == "fn"
        assert _classify_error("malicious", "中") == "fn"

    def test_malicious_judged_high_no_error(self):
        assert _classify_error("malicious", "高") == ""
        assert _classify_error("malicious", "严重") == ""

    def test_borderline_no_classification(self):
        assert _classify_error("borderline", "低") == ""
        assert _classify_error("borderline", "高") == ""

    def test_unknown_actual_no_error(self):
        assert _classify_error("malicious", "未知") == ""
        assert _classify_error("benign", "") == ""


class TestLoadDataset:
    def test_default_dataset_loads(self):
        samples = load_dataset()
        assert len(samples) > 0
        for s in samples:
            assert "target" in s
            assert "expected_risk_level" in s

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_dataset(Path("/nonexistent/dataset.yaml"))


class TestEvalReport:
    def test_hit_rate_with_skips(self):
        report = EvalReport(mode="replay", total=5, passed=3, skipped=2)
        # evaluated = 5 - 2 = 3, passed = 3 → 100%
        assert report.hit_rate == 1.0

    def test_hit_rate_partial(self):
        report = EvalReport(mode="replay", total=4, passed=2, skipped=1)
        # evaluated = 4 - 1 = 3, passed = 2 → 0.667
        assert report.hit_rate == round(2 / 3, 3)

    def test_hit_rate_zero_evaluated(self):
        report = EvalReport(mode="replay", total=3, passed=0, skipped=3)
        assert report.hit_rate == 0.0

    def test_to_dict_roundtrip(self):
        report = EvalReport(mode="online", total=2, passed=1)
        report.samples.append(SampleResult(
            target="a.com", category="malicious", expected="高",
            actual="高", actual_independent="高", hit=True,
        ))
        d = report.to_dict()
        assert d["mode"] == "online"
        assert d["total"] == 2
        assert d["passed"] == 1
        assert len(d["samples"]) == 1
        assert d["samples"][0]["target"] == "a.com"


class TestRunEval:
    @pytest.mark.asyncio
    async def test_replay_mode_all_cached(self):
        """回放模式：缓存全部命中。"""
        agent = MagicMock()
        agent.analyze = AsyncMock()
        # 模拟缓存命中：返回带 token_usage 的结果
        agent.analyze.side_effect = [
            AnalysisResult(target="a.com", target_type="domain", risk_level="高",
                           token_usage={"total_tokens": 1000}),
            AnalysisResult(target="b.com", target_type="domain", risk_level="低",
                           token_usage={"total_tokens": 500}),
        ]
        # 用临时数据集
        import tempfile, yaml
        tmp = Path(tempfile.mktemp(suffix=".yaml"))
        tmp.write_text(yaml.dump({
            "samples": [
                {"target": "a.com", "expected_risk_level": ["高", "严重"], "category": "malicious"},
                {"target": "b.com", "expected_risk_level": "低", "category": "benign"},
            ]
        }))
        try:
            report = await run_eval(agent, dataset_path=tmp, online=False)
            assert report.total == 2
            assert report.passed == 2
            assert report.hit_rate == 1.0
            assert report.skipped == 0
        finally:
            tmp.unlink()

    @pytest.mark.asyncio
    async def test_false_positive_detection(self):
        """良性样本被判恶意 → 误报。"""
        agent = MagicMock()
        agent.analyze = AsyncMock(return_value=AnalysisResult(
            target="good.com", target_type="domain", risk_level="高",
            token_usage={"total_tokens": 500},
        ))
        import tempfile, yaml
        tmp = Path(tempfile.mktemp(suffix=".yaml"))
        tmp.write_text(yaml.dump({
            "samples": [
                {"target": "good.com", "expected_risk_level": "低", "category": "benign"},
            ]
        }))
        try:
            report = await run_eval(agent, dataset_path=tmp, online=False)
            assert report.passed == 0
            assert report.false_positive == 1
        finally:
            tmp.unlink()

    @pytest.mark.asyncio
    async def test_false_negative_detection(self):
        """恶意样本被判低 → 漏报。"""
        agent = MagicMock()
        agent.analyze = AsyncMock(return_value=AnalysisResult(
            target="evil.com", target_type="domain", risk_level="低",
            token_usage={"total_tokens": 500},
        ))
        import tempfile, yaml
        tmp = Path(tempfile.mktemp(suffix=".yaml"))
        tmp.write_text(yaml.dump({
            "samples": [
                {"target": "evil.com", "expected_risk_level": ["高", "严重"], "category": "malicious"},
            ]
        }))
        try:
            report = await run_eval(agent, dataset_path=tmp, online=False)
            assert report.passed == 0
            assert report.false_negative == 1
        finally:
            tmp.unlink()


class TestBaseline:
    def test_save_and_compare(self, tmp_path):
        report = EvalReport(mode="online", total=3, passed=2)
        bl = tmp_path / "baseline.json"
        save_baseline(report, bl)
        assert bl.exists()

        # 相同报告对比 → ok
        cmp = compare_baseline(report, bl)
        assert cmp["status"] == "ok"

    def test_compare_regression(self, tmp_path):
        baseline_report = EvalReport(mode="online", total=3, passed=3)
        bl = tmp_path / "baseline.json"
        save_baseline(baseline_report, bl)

        # 退化报告
        worse = EvalReport(mode="online", total=3, passed=1)
        cmp = compare_baseline(worse, bl)
        assert cmp["status"] == "regression"
        assert any("命中率退化" in r for r in cmp["regressions"])

    def test_compare_no_baseline(self, tmp_path):
        report = EvalReport(mode="replay", total=1, passed=1)
        cmp = compare_baseline(report, tmp_path / "nonexist.json")
        assert cmp["status"] == "no_baseline"
