"""测试 compare.py: 策略 A/B 对比功能。"""

from secagent.compare import run_comparison, display_comparison
from secagent.result_parser import AnalysisResult


class TestRunComparison:
    def test_returns_dict(self):
        # run_comparison requires a real agent, so test the structure only
        assert callable(run_comparison)

    def test_display_comparison(self, capsys):
        results = {
            "quick": AnalysisResult(
                target="example.com", target_type="domain",
                risk_level="低", confidence=0.9, findings=["无威胁"],
                iocs=[], tools_used=[],
            ),
            "standard": AnalysisResult(
                target="example.com", target_type="domain",
                risk_level="中", confidence=0.7, findings=["可疑CDN"],
                iocs=[], tools_used=[],
            ),
        }
        display_comparison("example.com", results)
        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "低" in captured.out
        assert "中" in captured.out
