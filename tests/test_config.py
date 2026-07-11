"""测试 config.py: 配置加载 + 模型路由。"""

from secagent.config import (
    load_config, LLMConfig, ModelRouter, MCPServerConfig, AgentConfig,
    DOMAIN_SERVERS, IP_SERVERS, CRITICAL_SERVERS, OPTIONAL_SERVERS,
)


class TestModelRouter:
    def test_select_by_depth(self):
        router = ModelRouter(fast="fast-model", standard="std-model", reasoning="reason-model")
        assert router.select("quick") == "fast-model"
        assert router.select("standard") == "std-model"
        assert router.select("deep") == "reason-model"

    def test_select_fallback(self):
        router = ModelRouter()  # all empty
        assert router.select("quick", "default-model") == "default-model"

    def test_partial_config(self):
        router = ModelRouter(fast="fast-model")
        assert router.select("quick") == "fast-model"
        assert router.select("deep", "default") == "default"  # reasoning not set


class TestServerGroups:
    def test_domain_servers_has_ctia(self):
        assert "ctia_domain" in DOMAIN_SERVERS
        assert "ctia_ip" in DOMAIN_SERVERS

    def test_ip_servers_has_iporg(self):
        assert "iporg" in IP_SERVERS
        assert "ctia_ip" in IP_SERVERS

    def test_optional_not_in_domain(self):
        assert "bocha_search" not in DOMAIN_SERVERS
        assert "exa" not in DOMAIN_SERVERS

    def test_critical_subset(self):
        assert CRITICAL_SERVERS.issubset(DOMAIN_SERVERS | IP_SERVERS)


class TestLoadConfig:
    def test_loads_from_yaml(self):
        cfg = load_config()
        assert cfg.llm.model  # should have a model
        assert cfg.llm.base_url  # should have base_url
        assert len(cfg.mcp_servers) > 0  # should have MCP servers

    def test_models_router_loaded(self):
        cfg = load_config()
        # May be empty if not configured, but should exist
        assert isinstance(cfg.models, ModelRouter)

    def test_agent_config_fields(self):
        cfg = load_config()
        assert cfg.max_iterations > 0
        assert cfg.timeout > 0
