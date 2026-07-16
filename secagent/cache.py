"""结果缓存：按 (target, depth) 缓存 AnalysisResult，带 TTL。

避免短时间内对同一目标重复全量分析（烧 token + 调工具）。命中缓存时
analyze 直接返回缓存结果，跳过 LLM 调用与 MCP 连接。

存储采用 SQLite（WAL 模式 + threading.Lock），与 monitor.py 保持一致。
缓存键为 (target, depth)；TTL 默认 1 小时，可按场景调整。
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ResultCache:
    """AnalysisResult 的 TTL 缓存。"""

    DEFAULT_TTL = 3600  # 默认 1 小时

    def __init__(self, home: Path, ttl: int = DEFAULT_TTL):
        self.db_path = home / "cache.db"
        self.ttl = ttl
        self.db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS results (
                target TEXT,
                depth TEXT,
                result_json TEXT,
                timestamp TEXT,
                PRIMARY KEY (target, depth)
            )
        """)
        self.db.commit()

    def get(self, target: str, depth: str) -> dict[str, Any] | None:
        """查询缓存。命中且未过期返回 result dict，否则 None。"""
        with self._lock:
            row = self.db.execute(
                "SELECT result_json, timestamp FROM results WHERE target=? AND depth=?",
                (target, depth),
            ).fetchone()
        if not row:
            return None
        try:
            ts = datetime.fromisoformat(row[1])
            if (datetime.now() - ts).total_seconds() > self.ttl:
                return None  # 过期
            return json.loads(row[0])
        except (ValueError, TypeError):
            return None

    def put(self, target: str, depth: str, result: dict[str, Any]) -> None:
        """写入/更新缓存（INSERT OR REPLACE）。"""
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO results (target, depth, result_json, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (target, depth, json.dumps(result, ensure_ascii=False),
                 datetime.now().isoformat()),
            )
            self.db.commit()

    def clear(self) -> int:
        """清空全部缓存，返回删除行数。"""
        with self._lock:
            cur = self.db.execute("DELETE FROM results")
            self.db.commit()
            return cur.rowcount

    def close(self) -> None:
        self.db.close()
