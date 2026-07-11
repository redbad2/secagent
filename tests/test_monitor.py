"""测试 monitor.py: 监控目标管理 + 快照 + 变化检测。"""

from pathlib import Path
from secagent.monitor import MonitorDB


class TestMonitorDB:
    def test_add_target(self, tmp_home):
        db = MonitorDB(tmp_home)
        added = db.add_target("example.com", "domain")
        assert added is True
        # Duplicate
        added2 = db.add_target("example.com", "domain")
        assert added2 is False

    def test_remove_target(self, tmp_home):
        db = MonitorDB(tmp_home)
        db.add_target("evil.com", "domain")
        removed = db.remove_target("evil.com")
        assert removed is True
        removed2 = db.remove_target("nonexistent.com")
        assert removed2 is False

    def test_list_targets(self, tmp_home):
        db = MonitorDB(tmp_home)
        db.add_target("a.com", "domain")
        db.add_target("1.2.3.4", "ip")
        targets = db.list_targets()
        assert len(targets) == 2
        assert any(t["target"] == "a.com" for t in targets)
        assert any(t["target"] == "1.2.3.4" for t in targets)

    def test_save_snapshot_detects_change(self, tmp_home):
        db = MonitorDB(tmp_home)
        db.add_target("test.com", "domain")
        # First snapshot
        changed1 = db.save_snapshot("test.com", "低", "safe", ["safe"])
        assert changed1 is True  # First time = change from None
        # Same risk -> no change
        changed2 = db.save_snapshot("test.com", "低", "still safe", ["safe"])
        assert changed2 is False
        # Risk changes -> change detected
        changed3 = db.save_snapshot("test.com", "高", "compromised!", ["C2"])
        assert changed3 is True

    def test_get_history(self, tmp_home):
        db = MonitorDB(tmp_home)
        db.add_target("hist.com", "domain")
        db.save_snapshot("hist.com", "低", "v1", [])
        db.save_snapshot("hist.com", "中", "v2", [])
        db.save_snapshot("hist.com", "高", "v3", [])
        history = db.get_history("hist.com")
        assert len(history) == 3
        # Most recent first
        assert history[0]["risk_level"] == "高"

    def test_get_enabled_targets(self, tmp_home):
        db = MonitorDB(tmp_home)
        db.add_target("a.com", "domain")
        db.add_target("b.com", "domain")
        enabled = db.get_enabled_targets()
        assert len(enabled) == 2
        assert "a.com" in enabled

    def test_persists_across_restart(self, tmp_home):
        db1 = MonitorDB(tmp_home)
        db1.add_target("persist.com", "domain")
        db1.close()
        db2 = MonitorDB(tmp_home)
        targets = db2.list_targets()
        assert len(targets) == 1
        assert targets[0]["target"] == "persist.com"
