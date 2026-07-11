"""测试 prompt_builder.py: 系统提示构建。"""

from secagent.prompt_builder import build_system_prompt, SECURITY_ANALYST_PERSONA
from secagent.learning import MemoryStore, Skill


class TestBuildSystemPrompt:
    def test_contains_persona(self):
        prompt = build_system_prompt("example.com", "domain")
        assert "安全分析 Agent" in prompt

    def test_contains_target(self):
        prompt = build_system_prompt("evil.com", "domain")
        assert "evil.com" in prompt
        assert "domain" in prompt

    def test_contains_depth(self):
        prompt = build_system_prompt("1.2.3.4", "ip", depth="deep")
        assert "deep" in prompt
        assert "深度分析" in prompt

    def test_quick_depth(self):
        prompt = build_system_prompt("1.2.3.4", "ip", depth="quick")
        assert "快速分析" in prompt

    def test_with_memory(self, tmp_home):
        mem = MemoryStore(tmp_home)
        mem.add("CDN误报模式记录")
        prompt = build_system_prompt("test.com", "domain", memory=mem)
        assert "CDN误报模式记录" in prompt

    def test_with_skills(self):
        skill = Skill(name="test-skill", trigger="domain", content="步骤1\n步骤2")
        prompt = build_system_prompt("test.com", "domain", skills=[skill])
        assert "test-skill" in prompt
        assert "步骤1" in prompt

    def test_no_memory_no_skills(self):
        prompt = build_system_prompt("test.com", "domain")
        assert "安全分析 Agent" in prompt
        assert "test.com" in prompt
