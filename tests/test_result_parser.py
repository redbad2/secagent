"""测试 result_parser.py: 结果解析 + 风险评分。"""

import json
from secagent.result_parser import (
    AnalysisResult, is_valid_ip, parse_analysis_result,
    compute_risk_score, THREAT_WEIGHTS, INFRA_TRUST,
)


class TestIsValidIP:
    def test_valid_ipv4(self):
        assert is_valid_ip("1.2.3.4") is True
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True

    def test_invalid_ipv4(self):
        assert is_valid_ip("256.1.1.1") is False
        assert is_valid_ip("1.2.3") is False
        assert is_valid_ip("1.2.3.4.5") is False
        assert is_valid_ip("abc") is False
        assert is_valid_ip("") is False

    def test_domain_not_ip(self):
        assert is_valid_ip("example.com") is False
        assert is_valid_ip("baidu.com") is False


class TestParseAnalysisResult:
    def test_json_block_extraction(self):
        llm_output = '''分析完成。

```json
{
  "risk_level": "高",
  "confidence": 0.85,
  "findings": ["C2服务器", "恶意软件分发"],
  "iocs": ["1.2.3.4"],
  "tools_used": ["ctia_domain"],
  "summary": "C2基础设施",
  "recommendation": "封禁"
}
```
'''
        result = parse_analysis_result("evil.com", "domain", llm_output, ["ctia_domain"])
        assert result.risk_level == "高"
        assert result.confidence == 0.85
        assert len(result.findings) == 2
        assert result.summary == "C2基础设施"
        assert result.recommendation == "封禁"

    def test_fallback_no_json(self):
        result = parse_analysis_result("safe.com", "domain", "该域名安全", [])
        assert result.risk_level == "未知"
        assert len(result.findings) > 0

    def test_bare_json(self):
        llm_output = '结论: {"risk_level": "中", "confidence": 0.5, "findings": ["可疑"]}'
        result = parse_analysis_result("suspicious.com", "domain", llm_output, [])
        assert result.risk_level == "中"

    def test_to_dict(self):
        result = AnalysisResult(
            target="test.com", target_type="domain",
            risk_level="低", confidence=0.9,
            findings=["safe"], summary="ok",
        )
        d = result.to_dict()
        assert d["target"] == "test.com"
        assert d["risk_level"] == "低"
        assert d["confidence"] == 0.9

    def test_to_markdown(self):
        result = AnalysisResult(
            target="evil.com", target_type="domain",
            risk_level="高", confidence=0.9,
            findings=["C2 detected"], iocs=["1.2.3.4"],
            tools_used=["ctia_domain__v1_domain"],
            summary="C2 infrastructure",
            recommendation="Block immediately",
        )
        md = result.to_markdown()
        assert "# 安全分析报告" in md
        assert "evil.com" in md
        assert "**高**" in md
        assert "C2 detected" in md
        assert "1.2.3.4" in md
        assert "ctia_domain__v1_domain" in md
        assert "Block immediately" in md


class TestComputeRiskScore:
    def test_c2_independent(self):
        score, level = compute_risk_score(["c2"], "independent", ["associated with malware"])
        assert level == "严重"
        assert score >= 0.8

    def test_phishing_cloudflare(self):
        score, level = compute_risk_score(["phishing"], "cloudflare", [])
        # 0.7 * 0.3 = 0.21 -> "中"
        assert level == "中"
        assert score < 0.5

    def test_no_threat(self):
        score, level = compute_risk_score([], "")
        assert level == "低"
        assert score == 0.1

    def test_malware_aws(self):
        score, level = compute_risk_score(["malware"], "aws", [])
        # 0.8 * 0.5 = 0.4 -> "中"
        assert level == "中"
