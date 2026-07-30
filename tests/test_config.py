"""测试 config.py: 配置加载 + 模型路由。"""

from secagent.config import (
    load_config, LLMConfig, ModelRouter, MCPServerConfig, AgentConfig,
    DOMAIN_SERVERS, IP_SERVERS, CRITICAL_SERVERS, OPTIONAL_SERVERS,
    validate_config,
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


class TestValidateConfig:
    def _cfg(self, **kw):
        defaults = dict(
            llm=LLMConfig(base_url="http://x/v1", api_key="k", model="m"),
            mcp_servers={},
        )
        defaults.update(kw)
        return AgentConfig(**defaults)

    def test_valid_config_no_errors(self):
        errors, warnings = validate_config(self._cfg())
        assert errors == []
        assert warnings == [] or warnings == ["未配置任何 MCP server，LLM 将仅基于自身知识分析"]

    def test_missing_api_key_is_error(self):
        cfg = self._cfg(llm=LLMConfig(base_url="http://x/v1", api_key="", model="m"))
        errors, _ = validate_config(cfg)
        assert any("api_key" in e for e in errors)

    def test_missing_base_url_is_error(self):
        cfg = self._cfg(llm=LLMConfig(base_url="", api_key="k", model="m"))
        errors, _ = validate_config(cfg)
        assert any("base_url" in e for e in errors)

    def test_fdp_missing_creds_is_warning(self):
        cfg = self._cfg(mcp_servers={
            "qianxin_fdp_domain": MCPServerConfig(
                name="qianxin_fdp_domain",
                url="https://fdp.qianxin.com/mcp/v1/domain/",
                headers={},
            ),
        })
        errors, warnings = validate_config(cfg)
        assert errors == []
        assert any("qianxin_fdp_domain" in w and "fdp-access" in w for w in warnings)

    def test_fdp_with_creds_no_warning(self):
        cfg = self._cfg(mcp_servers={
            "qianxin_fdp_domain": MCPServerConfig(
                name="qianxin_fdp_domain",
                url="https://fdp.qianxin.com/mcp/v1/domain/",
                headers={"fdp-access": "a", "fdp-secret": "s"},
            ),
        })
        _, warnings = validate_config(cfg)
        assert not any("qianxin_fdp_domain" in w for w in warnings)

    def test_ctia_missing_token_is_warning(self):
        cfg = self._cfg(mcp_servers={
            "ctia_domain": MCPServerConfig(
                name="ctia_domain",
                url="https://fdp.qianxin.com/mcp/v1/ctia/domain/",
                headers={},
            ),
        })
        _, warnings = validate_config(cfg)
        assert any("ctia_domain" in w and "x-authtoken" in w.lower() for w in warnings)

    def test_iporg_no_creds_needed(self):
        cfg = self._cfg(mcp_servers={
            "iporg": MCPServerConfig(name="iporg", url="https://mcp.iporg.dev", headers={}),
        })
        _, warnings = validate_config(cfg)
        assert not any("iporg" in w for w in warnings)


class TestToolRoutingConfig:
    """P1-2：tool_routing 配置。"""

    def test_default_routing(self):
        from secagent.config import DEFAULT_TOOL_ROUTING
        cfg = AgentConfig()
        assert cfg.tool_routing == DEFAULT_TOOL_ROUTING
        assert cfg.tool_routing["domain_threat_intel"][0] == "ctia_domain"
        assert "iporg" in cfg.tool_routing["ip_threat_intel"]

    def test_default_routing_isolated_copy(self):
        """默认值是副本，修改一个实例不影响其他实例。"""
        a = AgentConfig()
        a.tool_routing["domain_threat_intel"].append("x")
        b = AgentConfig()
        assert "x" not in b.tool_routing["domain_threat_intel"]

    def test_load_config_custom_routing(self, tmp_path, monkeypatch):
        """config.yaml 中的 tool_routing 覆盖默认值。"""
        import secagent.config as cfg_mod
        monkeypatch.setattr(cfg_mod, "SECAGENT_HOME", tmp_path)
        (tmp_path / "config.yaml").write_text(
            "llm:\n  base_url: http://x\n  api_key: k\n  model: m\n"
            "tool_routing:\n"
            "  domain_threat_intel: [qianxin_fdp_domain, ctia_domain]\n",
            encoding="utf-8",
        )
        # 隔离用户环境的 .env / .hermes 影响
        monkeypatch.setattr(cfg_mod, "_load_dotenv", lambda p: {})
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        cfg = load_config()
        assert cfg.tool_routing["domain_threat_intel"] == [
            "qianxin_fdp_domain", "ctia_domain",
        ]
        # 未配置的组被丢弃（用户自定义整体替换）
        assert "ip_threat_intel" not in cfg.tool_routing
