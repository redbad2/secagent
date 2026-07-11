"""测试 learning.py: 记忆 + 技能 + 会话存档 + 学习触发。"""

from pathlib import Path

from secagent.learning import (
    MemoryStore, SkillStore, SessionDB, Skill,
    LearningTrigger, LearningAssessment,
)
from secagent.result_parser import AnalysisResult


class TestMemoryStore:
    def test_add_dedup(self, tmp_home):
        mem = MemoryStore(tmp_home)
        mem.add("事实1")
        mem.add("事实2")
        mem.add("事实1")  # 重复
        assert mem.content.count("事实1") == 1
        assert "事实2" in mem.content

    def test_search(self, tmp_home):
        mem = MemoryStore(tmp_home)
        mem.add("CDN误报: Cloudflare IP")
        mem.add("正常记录")
        matches = mem.search("CDN")
        assert len(matches) == 1
        assert "Cloudflare" in matches[0]

    def test_remove(self, tmp_home):
        mem = MemoryStore(tmp_home)
        mem.add("删除我")
        mem.add("保留我")
        removed = mem.remove("删除")
        assert removed is True
        assert "删除我" not in mem.content
        assert "保留我" in mem.content

    def test_clear(self, tmp_home):
        mem = MemoryStore(tmp_home)
        mem.add("test")
        mem.clear()
        assert mem.content == ""

    def test_llm_compression(self, tmp_home):
        call_count = {"n": 0}
        def mock_compress(content, limit):
            call_count["n"] += 1
            return content[:limit] + "\n[compressed]"
        mem = MemoryStore(tmp_home, llm_compress_fn=mock_compress)
        mem.MEMORY_LIMIT = 50
        for i in range(10):
            mem.add(f"item {i}: " + "x" * 20)
        assert call_count["n"] > 0

    def test_compression_fallback(self, tmp_home):
        def bad_compress(content, limit):
            raise RuntimeError("LLM unavailable")
        mem = MemoryStore(tmp_home, llm_compress_fn=bad_compress)
        mem.MEMORY_LIMIT = 50
        for i in range(10):
            mem.add(f"fallback {i}: " + "y" * 20)
        assert len(mem.content) <= 50

    def test_persists_across_restart(self, tmp_home):
        mem1 = MemoryStore(tmp_home)
        mem1.add("persistent fact")
        mem1._save()
        mem2 = MemoryStore(tmp_home)
        assert "persistent fact" in mem2.content


class TestSkillStore:
    def test_load_builtin(self, tmp_home, builtin_skills_dir):
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        all_skills = skills.load_all()
        assert len(all_skills) >= 3
        names = [s.name for s in all_skills]
        assert "domain-security-analysis" in names
        assert "ip-security-analysis" in names

    def test_find_relevant_domain(self, tmp_home, builtin_skills_dir):
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        relevant = skills.find_relevant("domain", "example.com")
        assert any(s.name == "domain-security-analysis" for s in relevant)

    def test_find_relevant_ip(self, tmp_home, builtin_skills_dir):
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        relevant = skills.find_relevant("ip", "1.2.3.4")
        assert any(s.name == "ip-security-analysis" for s in relevant)

    def test_create_and_delete(self, tmp_home):
        skills = SkillStore(tmp_home)
        path = skills.create_skill("test-skill", "content", "test")
        assert path.exists()
        deleted = skills.delete_skill("test-skill")
        assert deleted is True
        assert not path.exists()

    def test_should_create_skill_dedup(self, tmp_home, builtin_skills_dir):
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        # "domain" trigger already exists -> should return False
        assert skills.should_create_skill(10, ["f1"], "domain") is False
        # novel trigger -> should return True
        assert skills.should_create_skill(10, ["f1"], "custom_type") is True
        # too few tools -> False
        assert skills.should_create_skill(3, ["f1"], "custom_type") is False


class TestSessionDB:
    def test_save_and_list(self, tmp_home):
        db = SessionDB(tmp_home)
        db.save("test.com", "domain", "summary", "低", [{"role": "user", "content": "hi"}])
        recent = db.list_recent()
        assert len(recent) == 1
        assert recent[0]["target"] == "test.com"

    def test_search(self, tmp_home):
        db = SessionDB(tmp_home)
        db.save("evil.com", "domain", "C2 detected", "高", [])
        results = db.search("C2")
        assert len(results) == 1
        assert results[0]["target"] == "evil.com"

    def test_clear(self, tmp_home):
        db = SessionDB(tmp_home)
        db.save("a.com", "domain", "s", "低", [])
        db.clear()
        assert len(db.list_recent()) == 0

    def test_persists_across_restart(self, tmp_home):
        db1 = SessionDB(tmp_home)
        db1.save("persist.com", "domain", "persist", "中", [])
        db1.close()
        db2 = SessionDB(tmp_home)
        assert len(db2.list_recent()) == 1


class TestLearningTrigger:
    def test_assess_low_risk_false_positive(self, tmp_home, builtin_skills_dir):
        mem = MemoryStore(tmp_home)
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        lt = LearningTrigger(skills=skills, memory=mem, llm_call=None)

        result = AnalysisResult(
            target="baidu.com", target_type="domain",
            risk_level="低", confidence=0.98,
            findings=["白名单域名", "CDN IP误报"],
            tools_used=["t"] * 20,
            summary="安全",
        )
        assessment = lt.assess("baidu.com", "domain", result, [], result.tools_used)
        assert len(assessment.memory_facts) > 0
        assert any("误报" in f for f in assessment.memory_facts)

    def test_assess_high_risk_ioc(self, tmp_home, builtin_skills_dir):
        mem = MemoryStore(tmp_home)
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        lt = LearningTrigger(skills=skills, memory=mem, llm_call=None)

        result = AnalysisResult(
            target="evil.com", target_type="domain",
            risk_level="严重", confidence=0.95,
            findings=["C2", "malware"],
            iocs=["1.2.3.4", "evil.com"],
            tools_used=["t"] * 15,
            summary="C2 infrastructure",
        )
        assessment = lt.assess("evil.com", "domain", result, [], result.tools_used)
        assert any("已知威胁" in f for f in assessment.memory_facts)

    def test_apply_updates_memory(self, tmp_home, builtin_skills_dir):
        mem = MemoryStore(tmp_home)
        skills = SkillStore(tmp_home, builtin_dir=builtin_skills_dir)
        lt = LearningTrigger(skills=skills, memory=mem, llm_call=None)

        assessment = LearningAssessment(
            should_create_skill=False,
            memory_facts=["误报模式: CDN IP 被标记但实际安全"],
        )
        actions = lt.apply(assessment, interactive=False)
        assert len(actions) > 0
        assert "误报模式" in mem.content
