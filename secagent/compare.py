"""分析策略 A/B 对比：对同一目标用不同配置分析，对比结果差异。

用法:
    secagent compare example.com                    # 对比 quick vs standard
    secagent compare example.com --depths quick,deep  # 指定对比的深度
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from rich.console import Console
from rich.table import Table

from secagent.result_parser import AnalysisResult

logger = logging.getLogger(__name__)
console = Console()


async def run_comparison(agent, target: str, depths: list[str]) -> dict[str, AnalysisResult]:
    """对同一目标用不同 depth 分析，返回 {depth: result}。"""
    results: dict[str, AnalysisResult] = {}

    try:
        await agent.connect()
        for depth in depths:
            console.print(f"[dim]分析 {target} (depth={depth})...[/dim]")
            try:
                result = await agent.analyze(target, depth=depth, interactive=False, batch=True)
                results[depth] = result
                console.print(f"  [green]完成: risk={result.risk_level}, "
                               f"tools={len(result.tools_used)}, "
                               f"conf={result.confidence:.0%}[/green]")
            except Exception as e:
                console.print(f"  [red]失败: {e}[/red]")
                results[depth] = AnalysisResult(
                    target=target, target_type="domain",
                    risk_level="错误", summary=str(e),
                )
    finally:
        await agent.disconnect()

    return results


def display_comparison(target: str, results: dict[str, AnalysisResult]):
    """渲染 A/B 对比结果。"""
    if len(results) < 2:
        console.print("[yellow]需要至少两种策略才能对比[/yellow]\n")
        return

    table = Table(title=f"策略对比: {target}")
    table.add_column("维度", style="bold cyan", no_wrap=True)
    for depth in results:
        table.add_column(depth, style="yellow")

    # 风险等级
    table.add_row("风险等级", *[results[d].risk_level for d in results])
    # 置信度
    table.add_row("置信度", *[f"{results[d].confidence:.0%}" for d in results])
    # 工具调用数
    table.add_row("工具调用数", *[str(len(results[d].tools_used)) for d in results])
    # 发现数
    table.add_row("发现数", *[str(len(results[d].findings)) for d in results])
    # IOC 数
    table.add_row("IOC 数", *[str(len(results[d].iocs)) for d in results])
    # 摘要
    table.add_row("摘要", *[(results[d].summary or "")[:40] for d in results])

    console.print(table)

    # 一致性分析
    risk_levels = {results[d].risk_level for d in results}
    if len(risk_levels) == 1:
        console.print(f"\n[green]策略一致: 风险等级均为 {risk_levels.pop()}[/green]")
    else:
        console.print(f"\n[yellow]策略分歧: 风险等级不一致 ({', '.join(risk_levels)})[/yellow]")
        console.print("[dim]建议人工复查分歧原因[/dim]")

    console.print()


def cmd_compare(agent, target: str, depths_str: str = "quick,standard"):
    """A/B 策略对比命令。"""
    depths = [d.strip() for d in depths_str.split(",") if d.strip()]
    if len(depths) < 2:
        console.print("[red]需要至少两种策略: --depths quick,standard[/red]\n")
        return

    console.print(f"\n[bold cyan]策略对比[/bold cyan] {target}")
    console.print(f"[dim]策略: {', '.join(depths)}[/dim]\n")

    results = asyncio.run(run_comparison(agent, target, depths))
    display_comparison(target, results)
