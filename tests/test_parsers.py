"""parsers 包测试：结构化解析层回归保护。

重点覆盖历史上出过 bug 的场景：
- FDP 斜杠日期解析（_parse_age 切片 bug 曾丢失 domain_age_days）
- per-server parser 结构化成功后 is_cdn_ip 补算（曾恒为 False）
- compute_cdn_flag 公共函数
- 结构化 vs generic 一致性（结构化不应比正则更窄）
"""

from __future__ import annotations

import json

import pytest

from secagent.parsers.fdp import FDPParser
from secagent.parsers.ctia import CTIAParser
from secagent.parsers.generic import regex_fallback, compute_cdn_flag, default_signals


# ====================================================================
# FDP _parse_age 日期解析（回归保护：斜杠格式曾因切片 bug 丢失）
# ====================================================================


class TestParseAge:
    """FDP._parse_age 各日期格式解析。"""

    def setup_method(self):
        self.parser = FDPParser()

    def test_slash_date(self):
        """回归：2020/05/01 曾因 len(fmt.replace('%','0')) 切片错误返回 None。"""
        age = self.parser._parse_age("2020/05/01")
        assert age is not None and age > 0

    def test_dash_date(self):
        age = self.parser._parse_age("2023-01-15")
        assert age is not None and age > 0

    def test_iso_datetime(self):
        age = self.parser._parse_age("2023-01-15T12:34:56")
        assert age is not None and age > 0

    def test_slash_and_dash_equivalent(self):
        """斜杠与横线分隔的同一日期应得到相同的年龄。"""
        slash = self.parser._parse_age("2020/05/01")
        dash = self.parser._parse_age("2020-05-01")
        assert slash == dash

    def test_invalid_returns_none(self):
        assert self.parser._parse_age("not a date") is None

    def test_empty_returns_none(self):
        assert self.parser._parse_age("") is None


# ====================================================================
# FDP 结构化解析 is_cdn_ip 补算（回归保护：曾恒为 False）
# ====================================================================


class TestFDPCdnFlag:
    """FDP 结构化解析成功后 is_cdn_ip 补算。"""

    def setup_method(self):
        self.parser = FDPParser()

    def test_cdn_org_detected(self):
        """回归：结构化成功时 is_cdn_ip 曾丢失，导致 agent CDN 误报抑制失效。"""
        rec = json.dumps([{"creation_date": "2020/05/01", "asn_org": "Cloudflare"}])
        sig = self.parser.parse(rec)
        assert sig["is_cdn_ip"] is True
        assert sig["domain_age_days"] is not None

    def test_non_cdn_no_false_positive(self):
        rec = json.dumps([{"creation_date": "2020/05/01", "asn_org": "CustomOrg"}])
        sig = self.parser.parse(rec)
        assert sig["is_cdn_ip"] is False

    def test_cdn_keyword_in_text(self):
        """CDN 关键词出现在非 asn_org 字段也应命中。"""
        rec = json.dumps([{"asn_org": "某公司", "cdn_provider": "cloudfront"}])
        sig = self.parser.parse(rec)
        assert sig["is_cdn_ip"] is True


# ====================================================================
# CTIA 结构化解析 is_cdn_ip 补算 + 标签提取
# ====================================================================


class TestCTIACdnFlag:
    """CTIA 结构化解析成功后 is_cdn_ip 补算。"""

    def setup_method(self):
        self.parser = CTIAParser()

    def test_cdn_org_detected(self):
        text = json.dumps({"data": {"tags": ["c2"], "confidence": 90, "asn_org": "akamai"}})
        sig = self.parser.parse(text)
        assert sig["is_cdn_ip"] is True
        assert sig["threat_labels"] == ["c2"]

    def test_non_cdn(self):
        text = json.dumps({"data": {"tags": ["phishing"], "confidence": 80}})
        sig = self.parser.parse(text)
        assert sig["is_cdn_ip"] is False
        assert sig["threat_labels"] == ["phishing"]

    def test_empty_classification_not_tagged(self):
        """空 classification 不应被当成威胁标签。"""
        text = json.dumps({"data": {"tags": ["c2"], "classification": ""}})
        sig = self.parser.parse(text)
        assert "" not in sig["threat_labels"]
        assert sig["threat_labels"] == ["c2"]

    def test_confidence_normalization(self):
        text = json.dumps({"data": {"confidence": 90}})
        sig = self.parser.parse(text)
        assert sig["confidence"] == pytest.approx(0.9)


# ====================================================================
# compute_cdn_flag 公共函数
# ====================================================================


class TestComputeCdnFlag:
    """compute_cdn_flag 公共函数。"""

    def test_cdn_keyword_in_text(self):
        assert compute_cdn_flag("hosted on cloudflare") is True

    def test_cdn_keyword_in_org(self):
        assert compute_cdn_flag("random text", "Akamai") is True

    def test_demoted_cdn_yes(self):
        assert compute_cdn_flag("[已降级 | cdn=yes]") is True

    def test_chinese_cdn_keyword(self):
        # 纯中文 CDN 关键词不受 lower() 影响
        assert compute_cdn_flag("网宿科技加速") is True

    def test_no_false_positive(self):
        assert compute_cdn_flag("hello world", "CustomOrg") is False

    def test_empty_inputs(self):
        assert compute_cdn_flag("") is False
        assert compute_cdn_flag(None) is False
        assert compute_cdn_flag("", "") is False


# ====================================================================
# 结构化 vs generic 一致性（结构化不应比正则更窄）
# ====================================================================


class TestStructuredVsGenericConsistency:
    """结构化解析不应比 generic 正则更窄——这是引入 parsers 包的初衷。"""

    def test_fdp_slash_date_matches_generic(self):
        """回归：结构化曾丢失斜杠日期，而 generic 能提取。"""
        rec = json.dumps([{"creation_date": "2020/05/01", "asn_org": "Cloudflare"}])
        structured = FDPParser().parse(rec)
        generic = regex_fallback(rec)
        assert structured["domain_age_days"] == generic["domain_age_days"]
        assert structured["is_cdn_ip"] == generic["is_cdn_ip"]

    def test_fdp_icp_consistency(self):
        # ensure_ascii=False 保留中文，让 generic 正则也能匹配 ICP 备案号
        rec = json.dumps([{"icp": "京ICP备12345号"}], ensure_ascii=False)
        structured = FDPParser().parse(rec)
        generic = regex_fallback(rec)
        assert structured["has_icp"] == generic["has_icp"] is True

    def test_fdp_fallback_on_demoted(self):
        """降级格式应交给 generic 正则解析。"""
        text = "[已降级 | tag=c2 | age=5d | cdn=yes]"
        sig = FDPParser().parse(text)
        assert sig["threat_labels"] == ["c2"]
        assert sig["domain_age_days"] == 5
        assert sig["is_cdn_ip"] is True

    def test_ctia_fallback_on_demoted(self):
        text = "[已降级 | tag=malware | conf=0.90]"
        sig = CTIAParser().parse(text)
        assert sig["threat_labels"] == ["malware"]
        assert sig["confidence"] == pytest.approx(0.9)

    def test_default_signals_shape(self):
        sig = default_signals()
        assert set(sig.keys()) == {
            "threat_labels", "domain_age_days", "has_icp",
            "infra_org", "confidence", "is_cdn_ip",
        }
        assert sig["threat_labels"] == []
        assert sig["domain_age_days"] is None
        assert sig["is_cdn_ip"] is False
