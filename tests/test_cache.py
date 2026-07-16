"""测试 cache.py: ResultCache TTL 缓存。"""

import time

import pytest

from secagent.cache import ResultCache


class TestResultCache:
    def test_miss_returns_none(self, tmp_home):
        cache = ResultCache(tmp_home)
        assert cache.get("example.com", "standard") is None

    def test_put_then_get_hit(self, tmp_home):
        cache = ResultCache(tmp_home)
        cache.put("example.com", "standard", {"target": "example.com", "risk_level": "低"})
        got = cache.get("example.com", "standard")
        assert got is not None
        assert got["risk_level"] == "低"

    def test_different_depth_separate(self, tmp_home):
        cache = ResultCache(tmp_home)
        cache.put("example.com", "quick", {"risk_level": "低"})
        cache.put("example.com", "deep", {"risk_level": "高"})
        assert cache.get("example.com", "quick")["risk_level"] == "低"
        assert cache.get("example.com", "deep")["risk_level"] == "高"

    def test_put_overwrites(self, tmp_home):
        cache = ResultCache(tmp_home)
        cache.put("x.com", "standard", {"risk_level": "低"})
        cache.put("x.com", "standard", {"risk_level": "高"})
        assert cache.get("x.com", "standard")["risk_level"] == "高"

    def test_expired_returns_none(self, tmp_home):
        cache = ResultCache(tmp_home, ttl=-1)  # 负 TTL：立即过期
        cache.put("x.com", "standard", {"risk_level": "低"})
        assert cache.get("x.com", "standard") is None

    def test_ttl_not_expired(self, tmp_home):
        cache = ResultCache(tmp_home, ttl=3600)
        cache.put("x.com", "standard", {"risk_level": "低"})
        time.sleep(0.01)
        assert cache.get("x.com", "standard") is not None

    def test_clear_removes_all(self, tmp_home):
        cache = ResultCache(tmp_home)
        cache.put("a.com", "standard", {"risk_level": "低"})
        cache.put("b.com", "quick", {"risk_level": "中"})
        n = cache.clear()
        assert n == 2
        assert cache.get("a.com", "standard") is None
        assert cache.get("b.com", "quick") is None

    def test_corrupt_json_returns_none(self, tmp_home):
        cache = ResultCache(tmp_home)
        # 直接写入损坏的 JSON
        cache.db.execute(
            "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?)",
            ("x.com", "standard", "{not valid json", "2026-01-01T00:00:00"),
        )
        cache.db.commit()
        assert cache.get("x.com", "standard") is None
