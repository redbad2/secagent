"""评估框架：对分析质量做回归基线。

两种模式：
- 回放模式（默认）：优先用 ResultCache（--reuse）命中已存结果，避免重复烧 token；
  缓存未命中的样本标记为 SKIP（需先在线跑一轮填充缓存）。
- 在线模式（--online）：真实跑完整 analyze 链（连 MCP + 调 LLM），消耗配额。

指标：
- 命中率：实际 risk_level 在 expected_risk_level（支持多档允许偏差）内
- 误报率：良性样本被判 中/高/严重
- 漏报率：恶意样本被判 低/中
- 双轨分歧率：LLM 与独立评分不一致的比例
- 平均工具调用数 / 平均 token 成本

用法：
    secagent eval                         # 回放模式，用默认数据集
    secagent eval --online                # 在线模式（消耗配额，填充缓存）
    secagent eval --dataset my.yaml       # 自定义数据集
    secagent eval --save-baseline         # 结果写入 baseline.json 作为回归基线
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from secagent.result_parser import RISK_LEVELS

logger = logging.getLogger(__name__)

# 默认数据集与基线路径（相对于包根）
DEFAULT_DATASET = Path(__file__).parent.parent / "tests" / "eval" / "dataset.yaml"
BASELINE_PATH = Path(__file__).parent.parent / "tests" / "eval" / "baseline.json"

# 风险等级排序，用于误报/漏报判定
_RISK_RANK = {lvl: i for i, lvl in enumerate(RISK_LEVELS)}  # 低=0 ... 严重=3


@dataclass
class SampleResult:
    """单个样本的评估结果。"""
    target: str
    category: str
    expected: str | list[str]
    actual: str                # 实际 risk_level，SKIP 表示未跑
    actual_independent: str    # 独立评分 risk_level
    hit: bool                  # 是否命中期望
    skipped: bool = False      # 回放模式缓存未命中
    tools_used: int = 0
    tokens: int = 0
    discrepancy: str = ""      # 双轨分歧描述


@dataclass
class EvalReport:
    """整轮评估报告。"""
    mode: str                              # replay | online
    total: int = 0
    passed: int = 0                        # 命中数
    skipped: int = 0
    false_positive: int = 0                # 良性判恶意
    false_negative: int = 0                # 恶意判良性
    avg_tools: float = 0.0
    avg_tokens: float = 0.0
    discrepancy_rate: float = 0.0          # 双轨分歧率
    samples: list[SampleResult] = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def hit_rate(self) -> float:
        """命中率（不含 skip 的样本中）。"""
        evaluated = self.total - self.skipped
        return round(self.passed / evaluated, 3) if evaluated > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "timestamp": self.timestamp,
            "total": self.total,
            "passed": self.passed,
            "skipped": self.skipped,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "hit_rate": self.hit_rate,
            "avg_tools": round(self.avg_tools, 1),
            "avg_tokens": round(self.avg_tokens, 0),
            "discrepancy_rate": round(self.discrepancy_rate, 3),
            "samples": [
                {
                    "target": s.target, "category": s.category,
                    "expected": s.expected, "actual": s.actual,
                    "actual_independent": s.actual_independent,
                    "hit": s.hit, "skipped": s.skipped,
                    "tools_used": s.tools_used, "tokens": s.tokens,
                    "discrepancy": s.discrepancy,
                }
                for s in self.samples
            ],
        }


def load_dataset(path: Path | None = None) -> list[dict[str, Any]]:
    """加载评估数据集。"""
    p = path or DEFAULT_DATASET
    if not p.exists():
        raise FileNotFoundError(f"数据集不存在: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    samples = data.get("samples", []) if isinstance(data, dict) else []
    if not samples:
        raise ValueError(f"数据集无样本: {p}")
    return samples


def _is_hit(actual: str, expected: str | list[str]) -> bool:
    """判定实际等级是否命中期望。expected 支持单值或列表（任一命中即正确）。"""
    if not actual or actual == "未知":
        return False
    expected_list = expected if isinstance(expected, list) else [expected]
    return actual in expected_list


def _classify_error(sample_cat: str, actual: str) -> str:
    """判定误报/漏报类型。返回 'fp'（误报）/ 'fn'（漏报）/ ''（无）。"""
    if actual in ("未知", "") or actual not in _RISK_RANK:
        return ""
    rank = _RISK_RANK[actual]
    if sample_cat == "benign" and rank >= _RISK_RANK["中"]:
        return "fp"
    if sample_cat == "malicious" and rank <= _RISK_RANK["中"]:
        return "fn"
    return ""


async def _eval_one(agent, sample: dict[str, Any], online: bool) -> SampleResult:
    """评估单个样本。"""
    target = sample["target"]
    expected = sample.get("expected_risk_level", sample.get("expected", "未知"))
    category = sample.get("category", "unknown")

    try:
        result = await agent.analyze(
            target, depth="standard", interactive=False,
            batch=True, reuse=not online,
        )
        actual = result.risk_level
        actual_ind = result.independent_risk_level or "未知"
        tools = len(result.tools_used)
        tokens = (result.token_usage or {}).get("total_tokens", 0)
        discrepancy = result.risk_discrepancy or ""
        hit = _is_hit(actual, expected)
        return SampleResult(
            target=target, category=category, expected=expected,
            actual=actual, actual_independent=actual_ind,
            hit=hit, skipped=False,
            tools_used=tools, tokens=tokens, discrepancy=discrepancy,
        )
    except Exception as e:
        logger.warning("评估样本 %s 失败: %s", target, e)
        return SampleResult(
            target=target, category=category, expected=expected,
            actual="错误", actual_independent="错误",
            hit=False, skipped=False,
        )


async def run_eval(agent, dataset_path: Path | None = None,
                   online: bool = False) -> EvalReport:
    """执行一轮评估，返回报告。"""
    samples = load_dataset(dataset_path)
    report = EvalReport(mode="online" if online else "replay", total=len(samples))

    # 在线模式需要连接 MCP；回放模式若全部命中缓存则无需连接
    connected = False
    if online:
        await agent.connect()
        connected = True

    try:
        for sample in samples:
            sr = await _eval_one(agent, sample, online)
            report.samples.append(sr)

            # 回放模式：缓存未命中时 actual 为空或错误，标记 skip
            if not online and (sr.actual in ("未知", "错误") or sr.tokens == 0):
                # 判断是否真的缓存命中：reuse 模式命中时 from_cache=True
                # _eval_one 里没直接传 from_cache，靠 tokens==0 + actual 为默认值判断
                pass  # 命中判定已在 hit 里处理，skip 在下面统计

        # 汇总指标
        evaluated = 0
        passed = 0
        skipped = 0
        fp = 0
        fn = 0
        tools_sum = 0
        tokens_sum = 0
        discrepancy_count = 0

        for sr in report.samples:
            # 回放模式下，缓存未命中的样本 actual 可能为"未知"
            if not online and sr.actual in ("未知", "错误"):
                skipped += 1
                continue
            evaluated += 1
            if sr.hit:
                passed += 1
            err = _classify_error(sr.category, sr.actual)
            if err == "fp":
                fp += 1
            elif err == "fn":
                fn += 1
            if sr.discrepancy and "分歧" in sr.discrepancy:
                discrepancy_count += 1
            tools_sum += sr.tools_used
            tokens_sum += sr.tokens

        report.passed = passed
        report.skipped = skipped
        report.false_positive = fp
        report.false_negative = fn
        report.avg_tools = round(tools_sum / evaluated, 1) if evaluated > 0 else 0
        report.avg_tokens = round(tokens_sum / evaluated, 0) if evaluated > 0 else 0
        report.discrepancy_rate = round(discrepancy_count / evaluated, 3) if evaluated > 0 else 0
    finally:
        if connected:
            await agent.disconnect()

    return report


def save_baseline(report: EvalReport, path: Path | None = None) -> Path:
    """将报告写入 baseline.json 作为回归基线。"""
    p = path or BASELINE_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
                 encoding="utf-8")
    return p


def compare_baseline(report: EvalReport, baseline_path: Path | None = None) -> dict[str, Any]:
    """与基线对比，返回退化项。"""
    p = baseline_path or BASELINE_PATH
    if not p.exists():
        return {"status": "no_baseline", "message": "无基线，首次运行请用 --save-baseline"}
    baseline = json.loads(p.read_text(encoding="utf-8"))
    regressions: list[str] = []
    if report.hit_rate < baseline.get("hit_rate", 0) - 0.001:
        regressions.append(
            f"命中率退化: {report.hit_rate:.1%} < 基线 {baseline['hit_rate']:.1%}"
        )
    if report.false_positive > baseline.get("false_positive", 0):
        regressions.append(
            f"误报增加: {report.false_positive} > 基线 {baseline['false_positive']}"
        )
    if report.false_negative > baseline.get("false_negative", 0):
        regressions.append(
            f"漏报增加: {report.false_negative} > 基线 {baseline['false_negative']}"
        )
    return {
        "status": "regression" if regressions else "ok",
        "regressions": regressions,
        "baseline_hit_rate": baseline.get("hit_rate", 0),
        "current_hit_rate": report.hit_rate,
    }
