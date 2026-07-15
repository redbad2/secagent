"""告警通知：监控检测到风险变化时，通过 webhook 推送告警。

配置（config.yaml）：
    notify:
      webhooks:
        - url: "https://hooks.example.com/alert"
      min_risk: "高"       # 可选：只在风险 >= 该等级时通知

通知格式（POST JSON body）：
    {
      "event": "monitor_change",
      "timestamp": "2026-07-15T10:00:00",
      "changes": [
        {"target": "example.com", "risk_level": "高", "summary": "..."}
      ],
      "total_changes": 1
    }
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# 风险等级排序（用于 min_risk 过滤）
_RISK_ORDER = {"低": 0, "中": 1, "高": 2, "严重": 3, "未知": 0, "错误": 0}


def _should_notify(risk_level: str, min_risk: str) -> bool:
    """判断该风险等级是否达到通知阈值。"""
    return _RISK_ORDER.get(risk_level, 0) >= _RISK_ORDER.get(min_risk, 0)


def send_webhook(url: str, payload: dict[str, Any], timeout: int = 10) -> tuple[bool, str]:
    """发送 webhook 通知。

    Returns:
        (success, message)
    """
    try:
        resp = httpx.post(url, json=payload, timeout=timeout)
        if resp.status_code < 400:
            return True, f"HTTP {resp.status_code}"
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except httpx.TimeoutException:
        return False, f"超时 ({timeout}s)"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def notify_changes(
    changes: list[tuple[str, str, str]],
    webhooks: list[str],
    min_risk: str = "",
) -> list[str]:
    """对监控变化列表发送 webhook 通知。

    Args:
        changes: [(target, risk_level, summary), ...]
        webhooks: webhook URL 列表
        min_risk: 最低通知风险等级（低于此等级不通知）

    Returns:
        已执行的通知结果列表（人类可读）
    """
    if not webhooks or not changes:
        return []

    # 按阈值过滤
    if min_risk:
        filtered = [(t, r, s) for t, r, s in changes if _should_notify(r, min_risk)]
    else:
        filtered = changes
    if not filtered:
        return ["变化未达通知阈值（min_risk={}），跳过".format(min_risk)]

    payload = {
        "event": "monitor_change",
        "timestamp": datetime.now().isoformat(),
        "changes": [
            {"target": t, "risk_level": r, "summary": (s or "")[:200]}
            for t, r, s in filtered
        ],
        "total_changes": len(filtered),
    }

    results: list[str] = []
    for url in webhooks:
        ok, msg = send_webhook(url, payload)
        if ok:
            results.append(f"webhook 通知成功: {url} ({msg})")
        else:
            results.append(f"webhook 通知失败: {url} ({msg})")
    return results
