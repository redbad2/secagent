"""自我学习层：持久记忆 + 技能存储 + 会话存档 + 学习触发。

借鉴 Hermes Agent 的三层模型，自己实现，完全透明可控。
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ====================================================================
# 第一层：持久记忆 (MEMORY.md)
# ====================================================================

class MemoryStore:
    """跨会话的稳定事实，注入每次系统提示。"""

    MEMORY_LIMIT = 2200  # 字符上限

    def __init__(self, home: Path, llm_compress_fn: Callable[[str, int], str] | None = None):
        self.memory_file = home / "MEMORY.md"
        self.content: str = self._load()
        self._llm_compress_fn = llm_compress_fn

    def _load(self) -> str:
        if self.memory_file.exists():
            return self.memory_file.read_text(encoding="utf-8").strip()
        return ""

    def _save(self) -> None:
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)
        from secagent.config import secure_write
        secure_write(self.memory_file, self.content)

    def add(self, fact: str) -> None:
        """添加稳定事实，自动去重。超限时优先 LLM 压缩，兜底截断。"""
        fact = fact.strip()
        if not fact or fact in self.content:
            return
        self.content = (self.content + "\n" + fact).strip()
        if len(self.content) > self.MEMORY_LIMIT:
            self._compress()
        self._save()
        logger.debug("记忆已更新: %s", fact[:50])

    def _compress(self) -> None:
        """压缩记忆到限制内。优先 LLM 压缩，兜底截断。"""
        if self._llm_compress_fn:
            try:
                compressed = self._llm_compress_fn(self.content, self.MEMORY_LIMIT)
                if compressed and len(compressed) <= self.MEMORY_LIMIT:
                    self.content = compressed.strip()
                    logger.info("记忆已通过 LLM 压缩: %d -> %d 字符",
                                len(self.content), len(compressed))
                    return
            except Exception as e:
                logger.warning("LLM 记忆压缩失败，回退到截断: %s", e)
        # 兜底：保留最近的记忆
        self.content = self.content[-self.MEMORY_LIMIT:]
        logger.info("记忆已截断到 %d 字符", self.MEMORY_LIMIT)

    def remove(self, keyword: str) -> bool:
        """删除包含关键词的行。"""
        lines = self.content.splitlines()
        new_lines = [l for l in lines if keyword.lower() not in l.lower()]
        if len(new_lines) == len(lines):
            return False
        self.content = "\n".join(new_lines).strip()
        self._save()
        return True

    def clear(self) -> None:
        self.content = ""
        self._save()

    def search(self, keyword: str) -> list[str]:
        return [l for l in self.content.splitlines() if keyword.lower() in l.lower()]


# ====================================================================
# 第二层：技能存储 (SKILL.md)
# ====================================================================

@dataclass
class Skill:
    """单个技能的元数据 + 内容。"""
    name: str
    trigger: str
    content: str
    created: str = ""
    file_path: Path = field(default=None, repr=False)  # type: ignore


class SkillStore:
    """可复用的分析方法，从分析经验中提炼。"""

    def __init__(self, home: Path, builtin_dir: Path | None = None):
        self.user_skills_dir = home / "skills"
        self.user_skills_dir.mkdir(parents=True, exist_ok=True)
        self.builtin_dir = builtin_dir

    def _all_skill_dirs(self) -> list[Path]:
        dirs = []
        if self.builtin_dir and self.builtin_dir.exists():
            dirs.extend(d for d in self.builtin_dir.iterdir() if d.is_dir())
        if self.user_skills_dir.exists():
            dirs.extend(d for d in self.user_skills_dir.iterdir() if d.is_dir())
        return dirs

    def _load_skill(self, skill_dir: Path) -> Skill | None:
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            return None
        text = skill_file.read_text(encoding="utf-8")
        name = skill_dir.name
        trigger = ""
        created = ""
        content = text

        # 解析 YAML frontmatter
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                frontmatter = parts[1].strip()
                content = parts[2].strip()
                for line in frontmatter.splitlines():
                    if line.startswith("name:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("trigger:"):
                        trigger = line.split(":", 1)[1].strip()
                    elif line.startswith("created:"):
                        created = line.split(":", 1)[1].strip()

        return Skill(name=name, trigger=trigger, content=content,
                     created=created, file_path=skill_file)

    def load_all(self) -> list[Skill]:
        """加载所有技能。"""
        skills = []
        for d in self._all_skill_dirs():
            skill = self._load_skill(d)
            if skill:
                skills.append(skill)
        return skills

    def find_relevant(self, target_type: str, target: str = "") -> list[Skill]:
        """匹配相关技能。"""
        all_skills = self.load_all()
        relevant = []
        ctx = f"{target_type} {target}".lower()
        for skill in all_skills:
            trigger = skill.trigger.lower()
            if not trigger:
                continue
            # 精确匹配 target_type 或关键词命中
            if trigger == target_type or trigger == "all":
                relevant.append(skill)
            elif any(kw.strip() in ctx for kw in trigger.split(",")):
                relevant.append(skill)
        return relevant

    def create_skill(self, name: str, content: str, trigger: str) -> Path:
        """创建新技能。"""
        safe_name = re.sub(r"[^a-z0-9_-]", "_", name.lower())
        skill_dir = self.user_skills_dir / safe_name
        skill_dir.mkdir(parents=True, exist_ok=True)
        skill_path = skill_dir / "SKILL.md"
        from secagent.config import secure_write
        secure_write(skill_path, (
            f"---\nname: {name}\ntrigger: {trigger}\n"
            f"created: {datetime.now().isoformat()}\n---\n{content}"
        ))
        logger.info("技能已创建: %s (%s)", safe_name, skill_path)
        return skill_path

    def delete_skill(self, name: str) -> bool:
        """删除技能。"""
        safe_name = re.sub(r"[^a-z0-9_-]", "_", name.lower())
        skill_dir = self.user_skills_dir / safe_name
        if skill_dir.exists():
            import shutil
            shutil.rmtree(skill_dir)
            return True
        return False

    def should_create_skill(
        self,
        tools_used_count: int,
        findings: list[str],
        target_type: str,
    ) -> bool:
        """评估是否值得创建技能。"""
        if tools_used_count < 8:
            return False
        if not findings:
            return False
        # 检查是否与现有技能重复
        existing = self.load_all()
        for s in existing:
            if s.trigger == target_type:
                return False
        return True


# ====================================================================
# 第三层：会话存档 (SQLite FTS5)
# ====================================================================

class SessionDB:
    """所有分析会话被索引，支持 FTS5 全文检索。"""

    def __init__(self, home: Path):
        import threading
        self.db_path = home / "sessions.db"
        self.db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        # 检查表是否存在且列数匹配，仅在缺失时创建
        cols = self.db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='sessions'"
        ).fetchone()
        if not cols or "messages" not in (cols[0] or ""):
            # 旧 schema 或不存在，重建
            self.db.execute("DROP TABLE IF EXISTS sessions")
            self.db.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS sessions USING fts5(
                    target, target_type, summary, risk_level,
                    messages, timestamp
                )
            """)
            self.db.commit()

    def save(
        self,
        target: str,
        target_type: str,
        summary: str,
        risk_level: str,
        messages: list[dict[str, Any]],
    ) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
                (
                    target,
                    target_type,
                    summary,
                    risk_level,
                    json.dumps(messages, ensure_ascii=False),
                    datetime.now().isoformat(),
                ),
            )
            self.db.commit()

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            cursor = self.db.execute(
                "SELECT target, target_type, summary, risk_level, timestamp "
                "FROM sessions WHERE sessions MATCH ? ORDER BY timestamp DESC LIMIT ?",
                (query, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "target": r[0],
                "target_type": r[1],
                "summary": r[2],
                "risk_level": r[3],
                "timestamp": r[4],
            }
            for r in rows
        ]

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            cursor = self.db.execute(
                "SELECT target, target_type, summary, risk_level, timestamp "
                "FROM sessions ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "target": r[0],
                "target_type": r[1],
                "summary": r[2],
                "risk_level": r[3],
                "timestamp": r[4],
            }
            for r in rows
        ]

    def get_session(self, target: str) -> dict[str, Any] | None:
        """获取指定目标的最新会话完整内容（含消息）。"""
        with self._lock:
            cursor = self.db.execute(
                "SELECT target, target_type, summary, risk_level, messages, timestamp "
                "FROM sessions WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
                (target,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "target": row[0],
            "target_type": row[1],
            "summary": row[2],
            "risk_level": row[3],
            "messages": json.loads(row[4]) if row[4] else [],
            "timestamp": row[5],
        }

    def get_session_by_index(self, index: int) -> dict[str, Any] | None:
        """按最近顺序获取会话（0=最新）。"""
        with self._lock:
            cursor = self.db.execute(
                "SELECT target, target_type, summary, risk_level, messages, timestamp "
                "FROM sessions ORDER BY timestamp DESC LIMIT 1 OFFSET ?",
                (index,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "target": row[0],
            "target_type": row[1],
            "summary": row[2],
            "risk_level": row[3],
            "messages": json.loads(row[4]) if row[4] else [],
            "timestamp": row[5],
        }

    def clear(self) -> None:
        with self._lock:
            self.db.execute("DELETE FROM sessions")
            self.db.commit()

    def close(self) -> None:
        self.db.close()


# ====================================================================
# 第四层：学习触发器 (LearningTrigger)
# ====================================================================

@dataclass
class LearningAssessment:
    """一次分析的事后学习评估结果。"""
    should_create_skill: bool = False
    skill_name: str = ""
    skill_trigger: str = ""
    memory_facts: list[str] = field(default_factory=list)
    reason: str = ""


class LearningTrigger:
    """分析后评估：是否创建技能、是否更新记忆。

    在 agent.analyze() 完成后调用，评估本次分析是否产生了
    可复用的知识（技能）或需要持久化的稳定事实（记忆）。
    """

    def __init__(
        self,
        skills: SkillStore,
        memory: MemoryStore,
        llm_call: Callable[[str, str], str] | None = None,
    ):
        self.skills = skills
        self.memory = memory
        self._llm_call = llm_call  # (system_prompt, user_prompt) -> response_text

    def assess(
        self,
        target: str,
        target_type: str,
        result: Any,  # AnalysisResult
        messages: list[dict[str, Any]],
        tools_used: list[str],
        interactive: bool = True,
    ) -> LearningAssessment:
        """评估一次分析的学习价值。

        Args:
            result: AnalysisResult 对象
            messages: 完整的 LLM 对话消息
            tools_used: 实际调用的工具列表
            interactive: True=交互模式(可提示用户), False=批处理模式(自动决策)
        """
        assessment = LearningAssessment()

        # --- 1. 技能创建评估 ---
        tool_count = len(tools_used)
        has_findings = bool(result.findings)

        if self.skills.should_create_skill(tool_count, result.findings or [], target_type):
            assessment.should_create_skill = True
            assessment.skill_name = self._derive_skill_name(result, target_type)
            assessment.skill_trigger = target_type
            assessment.reason = f"复杂分析({tool_count}个工具调用) + 有发现"
        elif tool_count >= 5 and has_findings and result.risk_level in ("高", "严重"):
            # 高风险 + 中等复杂度也值得记录
            assessment.should_create_skill = True
            assessment.skill_name = self._derive_skill_name(result, target_type)
            assessment.skill_trigger = target_type
            assessment.reason = f"高风险分析({result.risk_level}), {tool_count}个工具"

        # --- 2. 记忆更新评估 ---
        facts = self._extract_memory_facts(result, messages, target_type)
        assessment.memory_facts = facts

        return assessment

    def apply(
        self,
        assessment: LearningAssessment,
        interactive: bool = True,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> list[str]:
        """应用学习评估结果。

        Args:
            assessment: assess() 的返回值
            interactive: 是否交互模式
            confirm_fn: 确认回调，返回 True 表示用户同意创建技能

        Returns:
            已执行的操作列表（人类可读）
        """
        actions: list[str] = []

        # 创建技能
        if assessment.should_create_skill:
            should_create = True
            if interactive and confirm_fn:
                should_create = confirm_fn(
                    f"本次分析较复杂({assessment.reason})，"
                    f"是否创建可复用技能 '{assessment.skill_name}'？"
                )

            if should_create:
                # 如果有 LLM，让它提炼技能内容；否则用简单的消息摘要
                skill_content = self._extract_skill_content(assessment)
                if skill_content:
                    self.skills.create_skill(
                        name=assessment.skill_name,
                        content=skill_content,
                        trigger=assessment.skill_trigger,
                    )
                    actions.append(f"已创建技能: {assessment.skill_name}")

        # 更新记忆
        for fact in assessment.memory_facts:
            if fact not in self.memory.content:
                self.memory.add(fact)
                actions.append(f"已更新记忆: {fact[:50]}")

        return actions

    def _derive_skill_name(self, result: Any, target_type: str) -> str:
        """从分析结果推导技能名称。"""
        # 基于风险等级和目标类型
        risk = result.risk_level or "unknown"
        # 尝试从 findings 中提取关键词
        keywords = []
        for f in (result.findings or [])[:3]:
            for kw in ["C2", "phishing", "malware", "DGA", "botnet",
                       "scanner", "proxy", "CDN", "误报"]:
                if kw.lower() in f.lower():
                    keywords.append(kw.lower())
        if keywords:
            return f"{target_type}-{'-'.join(keywords[:2])}-pattern"
        return f"{target_type}-{risk}-analysis-{datetime.now().strftime('%m%d')}"

    def _extract_memory_facts(
        self,
        result: Any,
        messages: list[dict[str, Any]],
        target_type: str,
    ) -> list[str]:
        """从分析结果中提取值得持久化的事实。"""
        facts: list[str] = []

        # 误报模式：风险低但工具调用了威胁情报
        if result.risk_level == "低" and result.findings:
            for f in result.findings:
                # 包含"白名单"/"误报"/"CDN"/"合法"等关键词的发现
                for kw in ["白名单", "误报", "CDN", "合法", "whitelist", "false positive"]:
                    if kw.lower() in f.lower():
                        facts.append(f"误报模式: {f[:100]}")
                        break

        # 高风险目标的 IOC 值得记忆
        if result.risk_level in ("高", "严重") and result.iocs:
            for ioc in result.iocs[:3]:
                facts.append(f"已知威胁: {ioc}")

        # 摘要中的关键结论
        if result.summary and result.risk_level in ("高", "严重"):
            facts.append(f"{target_type}分析结论: {result.summary[:100]}")

        return facts

    def _extract_skill_content(self, assessment: LearningAssessment) -> str:
        """提取技能内容。

        如果有 LLM 可用，让它从对话历史中提炼分析方法；
        否则使用模板生成基础内容。
        """
        if self._llm_call:
            try:
                system = (
                    "你是一个安全分析技能提取器。从分析对话中提炼出可复用的分析步骤。\n"
                    "输出格式：Markdown，包含步骤编号和每步的工具调用说明。\n"
                    "不要包含具体目标的信息，只保留通用方法。"
                )
                user = f"技能名: {assessment.skill_name}\n触发: {assessment.skill_trigger}\n原因: {assessment.reason}"
                content = self._llm_call(system, user)
                if content and len(content) > 50:
                    return content.strip()
            except Exception as e:
                logger.warning("LLM 技能提取失败，使用模板: %s", e)

        # 模板兜底
        return (
            f"## {assessment.skill_name}\n\n"
            f"触发条件: {assessment.skill_trigger}\n"
            f"创建原因: {assessment.reason}\n"
            f"创建时间: {datetime.now().isoformat()}\n\n"
            f"### 分析步骤\n"
            f"1. 查询 CTIA 威胁情报\n"
            f"2. 查询 FDP 基础数据 (PDNS/WHOIS/TLS)\n"
            f"3. 对解析 IP 执行威胁情报查询\n"
            f"4. 查询关联资产和伴生域名\n"
            f"5. 综合评估风险等级\n"
        )
