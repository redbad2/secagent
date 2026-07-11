"""CLI 入口：argparse 子命令 + prompt_toolkit 交互式 REPL。

支持两种模式：
1. 子命令模式：secagent analyze example.com
2. 交互式模式：secagent（进入 REPL，支持斜杠命令补全）
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import threading
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from secagent.config import load_config, SECAGENT_HOME
from secagent.result_parser import is_valid_ip, detect_target_type

console = Console()

logger = logging.getLogger("secagent")

# ====================================================================
# Banner
# ====================================================================

def _build_banner():
    try:
        from secagent import __version__
        ver = __version__
    except (ImportError, AttributeError):
        ver = "dev"
    art = [
        "███████╗███████╗ ██████╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗",
        "██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝",
        "███████╗█████╗  ██║     ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ",
        "╚════██║██╔══╝  ██║     ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ",
        "███████║███████╗╚██████╗██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ",
        "╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝  ",
    ]
    max_w = max(len(l) for l in art)
    pad = 4
    inner = max_w + pad + 2
    border = "─" * inner
    lines = [f"  ┌{border}┐", f"  │{' ' * inner}│"]
    for l in art:
        padded = " " * pad + l + " " * (inner - pad - len(l))
        lines.append(f"  │{padded}│")
    lines.append(f"  │{' ' * inner}│")
    for text in [
        f"Security Analysis Agent  v{ver}",
        "",
        "输入 域名 / IP / 哈希 / CVE 开始分析",
        "输入 /help 查看所有命令",
    ]:
        lines.append(f"  │{text.center(inner)}│")
    lines.append(f"  │{' ' * inner}│")
    lines.append(f"  └{border}┘")
    return "\n" + "\n".join(lines) + "\n"

BANNER = _build_banner()

# ====================================================================
# Slash command definitions
# ====================================================================

SLASH_COMMANDS = {
    "/analyze": None,
    "/batch": None,
    "/skills": {
        "list": None,
        "show": None,
        "delete": None,
    },
    "/memory": {
        "show": None,
        "add": None,
        "search": None,
        "clear": None,
    },
    "/history": {
        "search": None,
        "show": None,
        "list": None,
        "clear": None,
    },
    "/config": {
        "show": None,
        "export": None,
        "model": None,
    },
    "/monitor": {
        "list": None,
        "add": None,
        "remove": None,
        "run": None,
        "history": None,
    },
    "/help": None,
    "/exit": None,
    "/quit": None,
}

SLASH_HELP = {
    "/analyze": "分析域名或IP: /analyze example.com 或 /analyze 1.2.3.4",
    "/batch": "批量分析: /batch targets.txt",
    "/skills": "技能管理: /skills list | /skills show <name> | /skills delete <name>",
    "/memory": "记忆管理: /memory show | /memory add <fact> | /memory search <kw> | /memory clear",
    "/history": "历史: /history list | /history show <目标名|#序号> | /history search <keyword> | /history clear",
    "/config": "配置: /config show | /config export [文件] | /config model <name>",
    "/monitor": "监控: /monitor list | /monitor add <target> | /monitor remove <target> | /monitor run | /monitor history <target>",
    "/end": "结束当前分析会话（在追问模式下）",
    "/new": "结束当前会话，开始新分析",
    "/help": "显示帮助",
    "/exit": "退出",
    "/quit": "退出",
}

PROMPT_STYLE = Style.from_dict({
    "prompt": "bold cyan",
    "": "white",
})


# ====================================================================
# Result display
# ====================================================================

def display_result(result, fmt: str = "text", output_file: str | None = None):
    """渲染分析结果。"""
    if fmt == "json":
        output_text = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    elif fmt == "markdown":
        output_text = result.to_markdown()
    else:
        # text format: render to console with Rich, return None for file
        risk_colors = {
            "低": "green", "中": "yellow",
            "高": "red", "严重": "bold red",
            "未知": "dim",
        }
        color = risk_colors.get(result.risk_level, "white")

        header = (
            f"[bold]目标:[/bold] {result.target}  "
            f"[bold]类型:[/bold] {result.target_type}  "
            f"[bold]风险:[/bold] [{color}]{result.risk_level}[/{color}]  "
            f"[bold]置信度:[/bold] {result.confidence:.0%}  "
            f"[dim]{result.timestamp[:19]}[/dim]"
        )
        console.print(Panel(header, title="分析结果", border_style="cyan"))

        if result.summary:
            console.print(f"\n[bold]摘要:[/bold] {result.summary}")

        if result.findings:
            console.print("\n[bold]发现:[/bold]")
            for f in result.findings:
                console.print(f"  - {f}")

        if result.iocs:
            console.print(f"\n[bold]IOC:[/bold]")
            for ioc in result.iocs:
                console.print(f"  - {ioc}")

        if result.tools_used:
            console.print(f"\n[bold]使用工具[/bold] ({len(result.tools_used)}): "
                           + ", ".join(result.tools_used))

        if result.recommendation:
            console.print(f"\n[bold]建议:[/bold] {result.recommendation}")

        console.print()
        return

    # json or markdown: print to stdout or file
    if output_file:
        Path(output_file).write_text(output_text, encoding="utf-8")
        console.print(f"[green]报告已保存: {output_file}[/green]\n")
    else:
        if fmt == "markdown":
            console.print(Markdown(output_text))
        else:
            print(output_text)


# ====================================================================
# Async runner: single event loop for entire agent lifecycle
# ====================================================================

async def _run_analysis(agent, target, depth, fmt, on_tool_call=None, on_thinking=None, on_learning=None, interactive=True, confirm_fn=None):
    """在单个事件循环中完成 connect -> analyze -> disconnect。"""
    try:
        await agent.connect()
        result = await agent.analyze(
            target, depth=depth,
            on_tool_call=on_tool_call,
            on_thinking=on_thinking,
            on_learning=on_learning,
            interactive=interactive,
            confirm_fn=confirm_fn,
        )
        return result
    finally:
        await agent.disconnect()


def run_analyze_sync(agent, target, fmt="text", depth="standard", output_file=None):
    """同步入口：用单个 asyncio.run 包裹完整生命周期。"""
    def on_tool_call(tool_name, args):
        console.print(f"  [dim]-> 调用工具: {tool_name}[/dim]")

    def on_thinking(text):
        # 截断过长的思考内容
        display = text[:500] + "..." if len(text) > 500 else text
        console.print(f"  [dim italic]💭 {display}[/dim italic]")

    def on_learning(actions):
        console.print("\n[bold magenta]学习触发:[/bold magenta]")
        for a in actions:
            console.print(f"  [magenta]* {a}[/magenta]")

    def confirm_fn(prompt):
        console.print(f"\n[yellow]{prompt}[/yellow]")
        try:
            answer = input("(y/n) > ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    try:
        result = asyncio.run(_run_analysis(
            agent, target, depth, fmt,
            on_tool_call=on_tool_call,
            on_thinking=on_thinking,
            on_learning=on_learning,
            interactive=True,
            confirm_fn=confirm_fn,
        ))
        display_result(result, fmt, output_file)
    except Exception as e:
        console.print(f"\n[red]分析失败: {e}[/red]\n")
        logger.exception("分析失败")


# 后台事件循环管理器：用于交互式 REPL 中的多轮追问
class _AsyncLoopRunner:
    """在后台线程中运行 asyncio 事件循环，支持跨线程提交协程。"""
    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        if self._loop is not None:
            return
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread:
                self._thread.join(timeout=5)
            self._loop = None
            self._thread = None

    def run(self, coro):
        """在后台循环中运行协程，阻塞等待结果。"""
        if self._loop is None:
            self.start()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()  # 阻塞直到完成


_loop_runner = _AsyncLoopRunner()


def run_analyze_interactive(agent, target, fmt="text", depth="standard", output_file=None):
    """交互模式入口：连接+分析，不断开连接。会话保持用于追问。

    使用后台事件循环，保持 MCP 连接跨多轮追问存活。
    """
    def on_tool_call(tool_name, args):
        console.print(f"  [dim]-> 调用工具: {tool_name}[/dim]")

    def on_thinking(text):
        display = text[:500] + "..." if len(text) > 500 else text
        console.print(f"  [dim italic]💭 {display}[/dim italic]")

    def on_learning(actions):
        console.print("\n[bold magenta]学习触发:[/bold magenta]")
        for a in actions:
            console.print(f"  [magenta]* {a}[/magenta]")

    def confirm_fn(prompt):
        console.print(f"\n[yellow]{prompt}[/yellow]")
        try:
            answer = input("(y/n) > ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    async def _run():
        await agent.connect(target_type=detect_target_type(target))
        result = await agent.analyze(
            target, depth=depth,
            on_tool_call=on_tool_call,
            on_thinking=on_thinking,
            on_learning=on_learning,
            interactive=True,
            confirm_fn=confirm_fn,
        )
        return result

    try:
        result = _loop_runner.run(_run())
        display_result(result, fmt, output_file)
    except Exception as e:
        console.print(f"\n[red]分析失败: {e}[/red]\n")
        logger.exception("分析失败")


# ====================================================================
# Slash command handlers
# ====================================================================

def cmd_help():
    table = Table(title="可用命令", show_header=True)
    table.add_column("命令", style="bold cyan", no_wrap=True)
    table.add_column("说明", style="white")
    for cmd, desc in SLASH_HELP.items():
        table.add_row(cmd, desc)
    console.print(table)
    console.print("\n[dim]也可以直接输入域名或IP进行分析，无需 /analyze 前缀[/dim]\n")


def cmd_skills(agent, action: str, args: str):
    skills = agent.skills.load_all()
    if action in ("list", ""):
        if not skills:
            console.print("[dim]暂无技能[/dim]\n")
            return
        table = Table(title="已注册技能")
        table.add_column("名称", style="cyan")
        table.add_column("触发", style="yellow")
        table.add_column("创建时间", style="dim")
        for s in skills:
            table.add_row(s.name, s.trigger, s.created[:10] if s.created else "")
        console.print(table)
        console.print()

    elif action == "show":
        name = args.strip()
        if not name:
            console.print("[red]用法: /skills show <name>[/red]")
            return
        for s in skills:
            if s.name == name or s.file_path and s.file_path.parent.name == name:
                console.print(Markdown(f"---\nname: {s.name}\ntrigger: {s.trigger}\n---\n{s.content}"))
                console.print()
                return
        console.print(f"[red]技能不存在: {name}[/red]\n")

    elif action == "delete":
        name = args.strip()
        if not name:
            console.print("[red]用法: /skills delete <name>[/red]")
            return
        if agent.skills.delete_skill(name):
            console.print(f"[green]已删除技能: {name}[/green]\n")
        else:
            console.print(f"[red]技能不存在: {name}[/red]\n")


def cmd_memory(agent, action: str, args: str):
    if action in ("show", ""):
        if agent.memory.content:
            console.print(Panel(agent.memory.content, title="MEMORY.md",
                                border_style="cyan"))
        else:
            console.print("[dim]记忆为空[/dim]")
        console.print()

    elif action == "add":
        fact = args.strip()
        if not fact:
            console.print("[red]用法: /memory add <fact>[/red]")
            return
        agent.memory.add(fact)
        console.print(f"[green]已添加[/green]\n")

    elif action == "search":
        kw = args.strip()
        if not kw:
            console.print("[red]用法: /memory search <keyword>[/red]")
            return
        matches = agent.memory.search(kw)
        if matches:
            for m in matches:
                console.print(f"  {m}")
        else:
            console.print(f"[dim]未找到 '{kw}'[/dim]")
        console.print()

    elif action == "clear":
        agent.memory.clear()
        console.print("[green]记忆已清空[/green]\n")


def cmd_history(agent, action: str, args: str):
    if action in ("list", ""):
        rows = agent.sessions.list_recent(limit=20)
        if not rows:
            console.print("[dim]暂无历史[/dim]\n")
            return
        table = Table(title="最近分析")
        table.add_column("#", style="dim")
        table.add_column("目标", style="cyan")
        table.add_column("类型", style="dim")
        table.add_column("风险", style="yellow")
        table.add_column("摘要", style="white")
        table.add_column("时间", style="dim")
        for i, r in enumerate(rows):
            table.add_row(
                str(i),
                r["target"], r["target_type"],
                r["risk_level"],
                (r["summary"] or "")[:50],
                r["timestamp"][:19],
            )
        console.print(table)
        console.print("\n[dim]使用 /history show <目标名> 或 /history show #序号 查看完整内容[/dim]\n")

    elif action == "show":
        target_or_idx = args.strip()
        if not target_or_idx:
            console.print("[red]用法: /history show <目标名> 或 /history show #序号[/red]\n")
            return

        session_data = None
        if target_or_idx.startswith("#"):
            try:
                idx = int(target_or_idx[1:])
                session_data = agent.sessions.get_session_by_index(idx)
            except ValueError:
                console.print("[red]序号格式错误，如 #0[/red]\n")
                return
        else:
            session_data = agent.sessions.get_session(target_or_idx)

        if not session_data:
            console.print(f"[red]未找到: {target_or_idx}[/red]\n")
            return

        # 显示会话元信息
        risk_colors = {"低": "green", "中": "yellow", "高": "red", "严重": "bold red"}
        color = risk_colors.get(session_data["risk_level"], "white")
        console.print(Panel(
            f"[bold]目标:[/bold] {session_data['target']}  "
            f"[bold]风险:[/bold] [{color}]{session_data['risk_level']}[/{color}]  "
            f"[dim]{session_data['timestamp'][:19]}[/dim]",
            title="历史会话", border_style="cyan",
        ))

        if session_data["summary"]:
            console.print(f"\n[bold]摘要:[/bold] {session_data['summary']}")

        # 显示对话记录
        messages = session_data.get("messages", [])
        if messages:
            console.print(f"\n[bold]对话记录[/bold] ({len(messages)} 条消息):")
            for msg in messages:
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role == "system":
                    console.print(f"  [dim][system] {content[:80]}...[/dim]")
                elif role == "user":
                    console.print(f"  [bold cyan][用户][/bold cyan] {content}")
                elif role == "assistant":
                    if content:
                        console.print(f"  [bold green][助手][/bold green] {content[:200]}{'...' if len(content)>200 else ''}")
                    tc = msg.get("tool_calls", [])
                    if tc:
                        for t in tc:
                            fname = t.get("function", {}).get("name", "")
                            console.print(f"    [dim]-> 调用工具: {fname}[/dim]")
                elif role == "tool":
                    console.print(f"    [dim][工具结果] {content[:120]}{'...' if len(content)>120 else ''}[/dim]")
        console.print()

    elif action == "search":
        q = args.strip()
        if not q:
            console.print("[red]用法: /history search <keyword>[/red]\n")
            return
        rows = agent.sessions.search(q, limit=10)
        if not rows:
            console.print(f"[dim]未找到 '{q}'[/dim]\n")
            return
        table = Table(title=f"搜索: {q}")
        table.add_column("#", style="dim")
        table.add_column("目标", style="cyan")
        table.add_column("风险", style="yellow")
        table.add_column("摘要", style="white")
        table.add_column("时间", style="dim")
        for i, r in enumerate(rows):
            table.add_row(
                str(i),
                r["target"], r["risk_level"],
                (r["summary"] or "")[:50],
                r["timestamp"][:19],
            )
        console.print(table)
        console.print()

    elif action == "clear":
        agent.sessions.clear()
        console.print("[green]历史已清空[/green]\n")


def cmd_config(agent, action: str, args: str):
    if action in ("show", ""):
        table = Table(title="当前配置")
        table.add_column("键", style="cyan")
        table.add_column("值", style="yellow")
        table.add_row("model", agent.config.llm.model)
        table.add_row("base_url", agent.config.llm.base_url[:50] + "..." if len(agent.config.llm.base_url) > 50 else agent.config.llm.base_url)
        table.add_row("api_key", "***" if agent.config.llm.api_key else "[red]未设置[/red]")
        table.add_row("max_iterations", str(agent.config.max_iterations))
        table.add_row("secagent_home", str(agent.config.secagent_home))
        table.add_row("mcp_servers", ", ".join(agent.config.mcp_servers.keys()))
        console.print(table)
        console.print()

    elif action == "export":
        # 导出完整配置（含 key），用于复制到新机器
        import yaml as _yaml
        import re as _re
        output = args.strip() or str(agent.config.secagent_home / "config.export.yaml")

        def _resolve_env(val):
            """将 ${VAR_NAME} 替换为环境变量的实际值。"""
            if not isinstance(val, str):
                return val
            def _replace(m):
                return os.environ.get(m.group(1), m.group(0))
            return _re.sub(r'\$\{(\w+)\}', _replace, val)

        config = {
            "llm": {
                "base_url": agent.config.llm.base_url,
                "api_key": agent.config.llm.api_key,
                "model": agent.config.llm.model,
                "temperature": agent.config.llm.temperature,
            },
            "agent": {
                "max_iterations": agent.config.max_iterations,
                "timeout": agent.config.timeout,
            },
            "web_fetch": {
                "enabled": agent.config.web_fetch_enabled,
                "verify_ssl": agent.config.web_fetch_verify_ssl,
            },
            "exa": {"enabled": agent.config.exa_enabled},
            "mcp_servers": {},
        }
        for name, conf in agent.config.mcp_servers.items():
            server = {"url": conf.url}
            if conf.headers:
                server["headers"] = {k: _resolve_env(v) for k, v in conf.headers.items()}
            config["mcp_servers"][name] = server
        text = _yaml.dump(config, default_flow_style=False, allow_unicode=True, sort_keys=False)
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]配置已导出到: {output}[/green]")
        console.print(f"[dim]复制到新机器的 ~/.secagent/config.yaml 即可使用[/dim]\n")

    elif action == "model":
        model = args.strip()
        if model:
            agent.config.llm.model = model
            console.print(f"[green]模型已切换: {model}[/green]\n")
        else:
            console.print(f"当前模型: {agent.config.llm.model}\n")


def cmd_analyze(agent, target: str, fmt: str = "text", depth: str = "standard",
                output_file=None, interactive_mode: bool = False):
    """分析目标。interactive_mode=True 时不断开连接（用于 REPL 追问）。"""
    target = target.strip()
    if not target:
        console.print("[red]错误: 请提供目标域名或IP[/red]")
        console.print("用法: /analyze example.com 或 /analyze 1.2.3.4\n")
        return

    target_type = detect_target_type(target)
    type_labels = {"domain": "域名", "ip": "IP", "hash": "样本哈希", "cve": "CVE漏洞"}
    console.print(f"\n[bold cyan]分析目标:[/bold cyan] {target} ({type_labels.get(target_type, target_type)})")
    console.print(f"[dim]模型: {agent.config.llm.model} | 深度: {depth} | 最大迭代: {agent.config.max_iterations}[/dim]\n")

    if interactive_mode:
        # 交互模式：连接+分析，不断开（保持会话用于追问）
        run_analyze_interactive(agent, target, fmt, depth, output_file)
    else:
        # 子命令模式：完整生命周期 connect->analyze->disconnect
        run_analyze_sync(agent, target, fmt, depth, output_file)


async def _run_batch(agent, targets, concurrency=3):
    """批量分析：并行分析多个目标。

    Args:
        agent: SecurityAgent 实例
        targets: 目标列表
        concurrency: 最大并发数（默认 3，避免 API 限流）
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async def _analyze_one(i, t):
        async with semaphore:
            console.print(f"[dim]分析 {i}/{len(targets)}: {t}[/dim]")
            try:
                result = await agent.analyze(t, depth="quick", interactive=False)
                return (t, result.risk_level, (result.summary or "")[:40])
            except Exception as e:
                return (t, "错误", str(e)[:40])

    try:
        await agent.connect()
        tasks = [_analyze_one(i, t) for i, t in enumerate(targets, 1)]
        results = await asyncio.gather(*tasks)
    finally:
        await agent.disconnect()
    return list(results)


def cmd_batch(agent, filepath: str):
    path = Path(filepath.strip())
    if not path.exists():
        console.print(f"[red]文件不存在: {filepath}[/red]\n")
        return
    targets = [l.strip() for l in path.read_text().splitlines() if l.strip()]
    console.print(f"\n[bold cyan]批量分析[/bold cyan] {len(targets)} 个目标\n")

    results = asyncio.run(_run_batch(agent, targets))

    table = Table(title="批量分析结果")
    table.add_column("#", style="dim")
    table.add_column("目标", style="cyan")
    table.add_column("风险", style="yellow")
    table.add_column("摘要", style="white")
    for i, (t, risk, summary) in enumerate(results, 1):
        table.add_row(str(i), t, risk, summary)

    console.print(table)
    console.print()


# ====================================================================
# Monitor command
# ====================================================================

def cmd_update():
    """升级 secagent：自动检测安装方式并执行升级。"""
    import subprocess
    import sys
    from pathlib import Path

    console.print("[bold cyan]secagent 升级[/bold cyan]\n")

    # 检测当前版本
    from secagent import __version__
    console.print(f"当前版本: {__version__}")

    # 检测安装方式
    pkg_dir = Path(__file__).parent.parent
    is_dev = (pkg_dir / ".git").exists()

    if is_dev:
        # 开发模式：git pull + pip install -e .
        console.print("[dim]检测到开发模式（git 仓库）[/dim]")
        console.print("正在拉取最新代码...")
        r = subprocess.run(["git", "pull"], capture_output=True, text=True, cwd=str(pkg_dir))
        if r.returncode == 0:
            console.print(f"[green]{r.stdout.strip()}[/green]")
        else:
            console.print(f"[red]git pull 失败: {r.stderr.strip()}[/red]")
            return
        console.print("正在重新安装...")
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", str(pkg_dir)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            console.print("[green]升级完成[/green]")
        else:
            console.print(f"[red]pip install 失败: {r.stderr[-200:]}[/red]")
    else:
        # pipx / pip 安装
        pipx_home = Path.home() / ".local" / "pipx"
        if pipx_home.exists():
            console.print("[dim]检测到 pipx 环境[/dim]")
            console.print("正在升级...")
            r = subprocess.run(
                ["pipx", "upgrade", "secagent"],
                capture_output=True, text=True,
            )
            if r.returncode == 0:
                console.print(f"[green]{r.stdout.strip()}[/green]")
            else:
                console.print("[dim]upgrade 失败，尝试 reinstall...[/dim]")
                r = subprocess.run(
                    ["pipx", "reinstall", "secagent"],
                    capture_output=True, text=True,
                )
                if r.returncode == 0:
                    console.print("[green]reinstall 完成[/green]")
                else:
                    console.print(f"[red]升级失败: {r.stderr[-200:]}[/red]")
        else:
            console.print("[dim]尝试 pip 升级...[/dim]")
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade",
                 "git+https://github.com/redbad2/secagent.git"],
                capture_output=True, text=True,
            )
            if r.returncode == 0:
                console.print("[green]升级完成[/green]")
            else:
                console.print(f"[red]升级失败: {r.stderr[-200:]}[/red]")

    console.print("\n[dim]重启 secagent 以使用新版本[/dim]\n")


def cmd_monitor(agent, action: str, target: str = "", depth: str = "quick"):
    """定时监控管理。"""
    from secagent.monitor import MonitorDB
    from secagent.result_parser import is_valid_ip, detect_target_type

    db = MonitorDB(agent.config.secagent_home)

    if action in ("list", ""):
        targets = db.list_targets()
        if not targets:
            console.print("[dim]暂无监控目标[/dim]\n")
            db.close()
            return
        table = Table(title="监控目标")
        table.add_column("目标", style="cyan")
        table.add_column("类型", style="dim")
        table.add_column("上次风险", style="yellow")
        table.add_column("上次检查", style="dim")
        table.add_column("状态", style="green")
        for t in targets:
            table.add_row(
                t["target"], t["target_type"],
                t["last_risk"] or "-",
                (t["last_checked"] or "")[:19],
                "启用" if t["enabled"] else "禁用",
            )
        console.print(table)
        console.print()

    elif action == "add":
        if not target:
            console.print("[red]用法: secagent monitor add <target>[/red]\n")
            db.close()
            return
        target_type = "ip" if is_valid_ip(target) else "domain"
        added = db.add_target(target, target_type)
        if added:
            console.print(f"[green]已添加监控目标: {target} ({target_type})[/green]\n")
        else:
            console.print(f"[yellow]目标已存在: {target}[/yellow]\n")

    elif action == "remove":
        if not target:
            console.print("[red]用法: secagent monitor remove <target>[/red]\n")
            db.close()
            return
        removed = db.remove_target(target)
        if removed:
            console.print(f"[green]已移除监控目标: {target}[/green]\n")
        else:
            console.print(f"[red]目标不存在: {target}[/red]\n")

    elif action == "history":
        if not target:
            console.print("[red]用法: secagent monitor history <target>[/red]\n")
            db.close()
            return
        history = db.get_history(target)
        if not history:
            console.print(f"[dim]暂无历史: {target}[/dim]\n")
            db.close()
            return
        table = Table(title=f"监控历史: {target}")
        table.add_column("风险", style="yellow")
        table.add_column("摘要", style="white")
        table.add_column("时间", style="dim")
        for h in history:
            table.add_row(h["risk_level"], (h["summary"] or "")[:50], h["timestamp"][:19])
        console.print(table)
        console.print()

    elif action == "run":
        """执行一轮监控扫描，检测所有启用目标的变化。"""
        targets = db.get_enabled_targets()
        if not targets:
            console.print("[dim]没有启用的监控目标[/dim]\n")
            db.close()
            return

        console.print(f"[bold cyan]监控扫描[/bold cyan] {len(targets)} 个目标\n")

        changes = []

        async def _run_monitor():
            try:
                await agent.connect()
                for i, t in enumerate(targets, 1):
                    console.print(f"[dim]({i}/{len(targets)}) 分析 {t}...[/dim]")
                    try:
                        result = await agent.analyze(t, depth=depth, interactive=False)
                        changed = db.save_snapshot(
                            t, result.risk_level,
                            result.summary or "",
                            result.findings or [],
                        )
                        if changed:
                            changes.append((t, result.risk_level, result.summary))
                            console.print(f"  [yellow]变化检测: {t} -> {result.risk_level}[/yellow]")
                        else:
                            console.print(f"  [green]无变化: {t} ({result.risk_level})[/green]")
                    except Exception as e:
                        console.print(f"  [red]错误: {t}: {e}[/red]")
            finally:
                await agent.disconnect()

        asyncio.run(_run_monitor())

        if changes:
            console.print(f"\n[bold red]检测到 {len(changes)} 个变化:[/bold red]")
            for t, risk, summary in changes:
                console.print(f"  {t}: {risk} - {summary[:60]}")
        else:
            console.print(f"\n[green]所有目标无变化[/green]")
        console.print()

    db.close()


# ====================================================================
# Command dispatcher
# ====================================================================

def parse_and_execute(agent, input_str: str, interactive_mode: bool = False) -> bool:
    """解析并执行用户输入。返回 True 表示请求退出。"""
    input_str = input_str.strip()
    if not input_str:
        return False

    # 直接输入域名/IP（无斜杠前缀）
    if not input_str.startswith("/"):
        if is_valid_ip(input_str) or "." in input_str or detect_target_type(input_str) in ("hash", "cve"):
            cmd_analyze(agent, input_str, interactive_mode=interactive_mode)
        else:
            console.print(f"[yellow]未识别: {input_str}[/yellow]")
            console.print("[dim]输入 /help 查看命令，或直接输入域名/IP[/dim]\n")
        return False

    parts = input_str[1:].split(None, 1)
    cmd = "/" + parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    rest_parts = rest.split(None, 1)
    action = rest_parts[0] if rest_parts else ""
    args = rest_parts[1] if len(rest_parts) > 1 else ""

    if cmd in ("/exit", "/quit"):
        console.print("[dim]再见[/dim]")
        return True
    elif cmd == "/help":
        cmd_help()
    elif cmd == "/analyze":
        cmd_analyze(agent, rest, interactive_mode=interactive_mode)
    elif cmd == "/batch":
        cmd_batch(agent, rest)
    elif cmd == "/skills":
        cmd_skills(agent, action, args)
    elif cmd == "/memory":
        cmd_memory(agent, action, args)
    elif cmd == "/history":
        cmd_history(agent, action, args)
    elif cmd == "/config":
        cmd_config(agent, action, args)
    elif cmd == "/monitor":
        cmd_monitor(agent, action, rest.split()[0] if rest.split() else "", args)
    else:
        console.print(f"[red]未知命令: {cmd}[/red]")
        console.print("[dim]输入 /help 查看可用命令[/dim]\n")

    return False


# ====================================================================
# Main entry
# ====================================================================

def get_prompt_text():
    return HTML("<ansicyan><b>secagent></b></ansicyan> ")


def build_completer():
    return NestedCompleter.from_nested_dict(SLASH_COMMANDS)


def run_interactive(agent):
    """交互式 REPL。支持分析后的多轮追问。"""
    console.print(BANNER, style="cyan")

    history_file = SECAGENT_HOME / "cli_history"
    session = PromptSession(
        history=FileHistory(str(history_file)),
        completer=build_completer(),
        auto_suggest=AutoSuggestFromHistory(),
        style=PROMPT_STYLE,
        complete_while_typing=True,
    )

    # 会话状态
    in_session = False  # 是否在分析会话中（可追问）
    session_target = ""

    while True:
        try:
            # 根据是否在会话中，切换提示符
            if in_session:
                prompt_text = HTML(f"<ansicyan><b>secagent({session_target})></b></ansicyan> ")
            else:
                prompt_text = get_prompt_text()

            user_input = session.prompt(prompt_text)

            # 会话模式下的输入处理
            if in_session:
                if user_input.strip() in ("/end", "/done", "/exit", "/quit"):
                    # 结束会话
                    console.print("[dim]结束分析会话...[/dim]")
                    _end_session_sync(agent)
                    in_session = False
                    session_target = ""
                    if user_input.strip() in ("/exit", "/quit"):
                        console.print("[dim]再见[/dim]")
                        break
                    console.print("[green]会话已结束。可输入新目标开始新分析。[/green]\n")
                    continue
                elif user_input.strip() == "/new":
                    # 开始新分析（先结束当前）
                    _end_session_sync(agent)
                    in_session = False
                    session_target = ""
                    continue
                elif user_input.strip().startswith("/"):
                    # 会话中的斜杠命令（除了 /end /new /exit /quit）
                    should_exit = parse_and_execute(agent, user_input)
                    if should_exit:
                        _end_session_sync(agent)
                        break
                else:
                    # 追问
                    question = user_input.strip()
                    if not question:
                        continue
                    _ask_sync(agent, question)
                    continue

            # 非会话模式
            should_exit = parse_and_execute(agent, user_input, interactive_mode=True)

            # 检查是否进入了会话（analyze 后）
            if agent._session_active and not should_exit:
                in_session = True
                session_target = agent._session_target
                console.print(f"\n[dim]分析完成。你可以继续追问，输入 /end 结束会话，或 /new 分析新目标。[/dim]\n")

            if should_exit:
                break
        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C - 输入 /exit 退出[/dim]")
        except EOFError:
            console.print("\n[dim]再见[/dim]")
            break
        except Exception as e:
            console.print(f"[red]错误: {e}[/red]\n")
            logger.exception("REPL 错误")


def _ask_sync(agent, question: str):
    """在当前会话中追问。使用后台事件循环保持 MCP 连接。"""
    def on_tool_call(tool_name, args):
        console.print(f"  [dim]-> 调用工具: {tool_name}[/dim]")

    def on_thinking(text):
        display = text[:500] + "..." if len(text) > 500 else text
        console.print(f"  [dim italic]💭 {display}[/dim italic]")

    async def _run():
        try:
            response = await agent.ask(question, on_tool_call=on_tool_call, on_thinking=on_thinking)
            console.print(f"\n{response}\n")
        except Exception as e:
            console.print(f"\n[red]追问失败: {e}[/red]\n")

    _loop_runner.run(_run())


async def _end_session_async(agent):
    """结束分析会话（async 版本）。"""
    def on_learning(actions):
        console.print("\n[bold magenta]学习触发:[/bold magenta]")
        for a in actions:
            console.print(f"  [magenta]* {a}[/magenta]")

    def confirm_fn(prompt):
        console.print(f"\n[yellow]{prompt}[/yellow]")
        try:
            answer = input("(y/n) > ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    try:
        await agent.end_session(
            on_learning=on_learning,
            interactive=True,
            confirm_fn=confirm_fn,
        )
    except Exception:
        pass


def _end_session_sync(agent):
    """结束分析会话（同步入口，使用后台循环）。"""
    _loop_runner.run(_end_session_async(agent))


def main():
    parser = argparse.ArgumentParser(
        prog="secagent",
        description="安全分析 Agent - 域名/IP 安全风险判断",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="详细日志")
    subparsers = parser.add_subparsers(dest="command")

    p_analyze = subparsers.add_parser("analyze", help="分析域名或IP")
    p_analyze.add_argument("target", help="域名或IP地址")
    p_analyze.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p_analyze.add_argument("--depth", choices=["quick", "standard", "deep"],
                           default="standard")
    p_analyze.add_argument("--output", "-o", help="输出到文件（支持 .json/.md/.txt）")

    p_batch = subparsers.add_parser("batch", help="批量分析")
    p_batch.add_argument("file", help="目标列表文件")
    p_batch.add_argument("--output", help="输出文件路径")

    p_skills = subparsers.add_parser("skills", help="技能管理")
    p_skills.add_argument("action", nargs="?", default="list")

    p_memory = subparsers.add_parser("memory", help="记忆管理")
    p_memory.add_argument("action", nargs="?", default="show")

    p_history = subparsers.add_parser("history", help="历史搜索")
    p_history.add_argument("action", nargs="?", default="list",
                           choices=["list", "show", "search", "clear"])
    p_history.add_argument("target", nargs="?", default="", help="目标名或 #序号")

    p_config = subparsers.add_parser("config", help="配置管理")
    p_config.add_argument("action", nargs="?", default="show")

    p_monitor = subparsers.add_parser("monitor", help="定时监控管理")
    p_monitor.add_argument("action", choices=["add", "remove", "list", "run", "history"],
                           default="list", nargs="?")
    p_monitor.add_argument("target", nargs="?", help="目标域名/IP (add/remove/history)")
    p_monitor.add_argument("--depth", choices=["quick", "standard"], default="quick")

    p_compare = subparsers.add_parser("compare", help="策略 A/B 对比")
    p_compare.add_argument("target", help="目标域名/IP")
    p_compare.add_argument("--depths", default="quick,standard",
                           help="对比的深度，逗号分隔 (如 quick,standard,deep)")

    p_update = subparsers.add_parser("update", help="升级 secagent")

    args = parser.parse_args()

    # 日志
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(name)s: %(message)s")
    # 抑制 MCP/httpx 的 INFO 日志噪音（HTTP请求、session协商等）
    # 用 filter 而非 setLevel，因为库可能自己加 handler 绕过 setLevel
    class _SuppressInfoFilter(logging.Filter):
        def filter(self, record):
            return record.levelno >= logging.WARNING
    for noisy in ("mcp", "httpx", "httpcore", "anyio", "urllib3"):
        lg = logging.getLogger(noisy)
        lg.setLevel(logging.WARNING)
        lg.addFilter(_SuppressInfoFilter())

    # 加载配置
    config = load_config()

    # 默认 max_iterations 提高到 20，给 LLM 足够空间完成分析+输出 JSON
    if config.max_iterations < 20:
        config.max_iterations = 20

    # 验证必要配置
    if not config.llm.api_key:
        console.print("[yellow]警告: LLM API key 未设置[/yellow]")
        console.print("[dim]请在 ~/.secagent/config.yaml 或环境变量中配置[/dim]\n")

    from secagent.agent import SecurityAgent
    agent = SecurityAgent(config)

    # 非交互式子命令
    if args.command == "analyze":
        cmd_analyze(agent, args.target, fmt=args.format, depth=args.depth,
                    output_file=args.output)
        agent.close()
        return
    elif args.command == "batch":
        cmd_batch(agent, args.file)
        agent.close()
        return
    elif args.command == "skills":
        cmd_skills(agent, args.action, "")
        agent.close()
        return
    elif args.command == "memory":
        cmd_memory(agent, args.action, "")
        agent.close()
        return
    elif args.command == "history":
        cmd_history(agent, args.action, args.target or "")
        agent.close()
        return
    elif args.command == "config":
        cmd_config(agent, args.action, "")
        agent.close()
        return
    elif args.command == "monitor":
        cmd_monitor(agent, args.action, args.target or "", args.depth)
        agent.close()
        return
    elif args.command == "compare":
        from secagent.compare import cmd_compare
        cmd_compare(agent, args.target, args.depths)
        agent.close()
        return
    elif args.command == "update":
        cmd_update()
        return

    # 交互式模式
    try:
        run_interactive(agent)
    finally:
        agent.close()


if __name__ == "__main__":
    main()
