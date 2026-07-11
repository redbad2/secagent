"""conftest.py - pytest 共享 fixtures。"""

import tempfile
from pathlib import Path

import pytest

from secagent.config import AgentConfig, LLMConfig, ModelRouter, MCPServerConfig


@pytest.fixture
def tmp_home():
    """临时 secagent home 目录。"""
    with tempfile.TemporaryDirectory(prefix="secagent-test-") as d:
        p = Path(d)
        (p / "skills").mkdir()
        (p / "memory").mkdir()
        (p / "logs").mkdir()
        yield p


@pytest.fixture
def builtin_skills_dir():
    """项目内置技能目录（包内）。"""
    return Path(__file__).parent.parent / "secagent" / "skills"


@pytest.fixture
def mock_config(tmp_home):
    """不连接真实 MCP 的测试配置。"""
    return AgentConfig(
        llm=LLMConfig(
            base_url="http://localhost:9999/v1",
            api_key="test-key",
            model="test-model",
        ),
        models=ModelRouter(
            fast="test-fast",
            standard="test-standard",
            reasoning="test-reasoning",
        ),
        mcp_servers={},
        max_iterations=5,
        timeout=10,
        secagent_home=tmp_home,
    )
