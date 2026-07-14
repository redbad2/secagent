"""定时监控：监控目标域名/IP 的安全状态变化。

使用 SQLite 存储监控列表和历史快照，通过对比上次分析结果检测变化。
不依赖系统 cron -- 可以配合系统 crontab 调用 `secagent monitor run`。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


class MonitorDB:
    """监控目标和历史快照的存储。"""

    def __init__(self, home: Path):
        self.db_path = home / "monitor.db"
        self.db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        import threading; self._lock = threading.Lock()
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                target TEXT PRIMARY KEY,
                target_type TEXT,
                added_at TEXT,
                last_checked TEXT,
                last_risk TEXT,
                enabled INTEGER DEFAULT 1
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                risk_level TEXT,
                summary TEXT,
                findings TEXT,
                timestamp TEXT,
                FOREIGN KEY (target) REFERENCES targets(target)
            )
        """)
        self.db.commit()

    def add_target(self, target: str, target_type: str) -> bool:
        """添加监控目标。返回 True=新增，False=已存在。"""
        existing = self.db.execute(
            "SELECT target FROM targets WHERE target = ?", (target,)
        ).fetchone()
        if existing:
            return False
        self.db.execute(
            "INSERT INTO targets (target, target_type, added_at, enabled) VALUES (?, ?, ?, 1)",
            (target, target_type, datetime.now().isoformat()),
        )
        self.db.commit()
        return True

    def remove_target(self, target: str) -> bool:
        cur = self.db.execute("DELETE FROM targets WHERE target = ?", (target,))
        self.db.execute("DELETE FROM snapshots WHERE target = ?", (target,))
        self.db.commit()
        return cur.rowcount > 0

    def list_targets(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT target, target_type, added_at, last_checked, last_risk, enabled "
            "FROM targets ORDER BY target"
        ).fetchall()
        return [
            {
                "target": r[0], "target_type": r[1], "added_at": r[2],
                "last_checked": r[3], "last_risk": r[4], "enabled": bool(r[5]),
            }
            for r in rows
        ]

    def get_enabled_targets(self) -> list[str]:
        rows = self.db.execute(
            "SELECT target FROM targets WHERE enabled = 1"
        ).fetchall()
        return [r[0] for r in rows]

    def save_snapshot(
        self,
        target: str,
        risk_level: str,
        summary: str,
        findings: list[str],
    ) -> bool:
        """保存快照并检测变化。返回 True=有变化。"""
        # 获取上次的风险等级
        prev = self.db.execute(
            "SELECT last_risk FROM targets WHERE target = ?", (target,)
        ).fetchone()
        prev_risk = prev[0] if prev else None

        changed = (prev_risk != risk_level)

        # 保存快照
        self.db.execute(
            "INSERT INTO snapshots (target, risk_level, summary, findings, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, risk_level, summary, json.dumps(findings, ensure_ascii=False),
             datetime.now().isoformat()),
        )
        # 更新目标状态
        self.db.execute(
            "UPDATE targets SET last_checked = ?, last_risk = ? WHERE target = ?",
            (datetime.now().isoformat(), risk_level, target),
        )
        self.db.commit()
        return changed

    def get_history(self, target: str, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT risk_level, summary, timestamp FROM snapshots "
            "WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        return [
            {"risk_level": r[0], "summary": r[1], "timestamp": r[2]}
            for r in rows
        ]

    def close(self):
        self.db.close()
