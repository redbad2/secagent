"""配置加载：YAML 文件 + 环境变量 + .env 文件，优先级递减。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


SECAGENT_HOME = Path(os.environ.get("SECAGENT_HOME", str(Path.home() / ".secagent")))


def secure_write(path: Path, data: str, encoding: str = "utf-8") -> None:
    """安全写入文件：O_CREAT|O_WRONLY|O_TRUNC，权限 0o600。

    fdopen 成功后会接管 fd 的所有权（包括异常时关闭），故不可在外层
    再 os.close(fd)，否则会 double-close 并可能误关被复用的其他 fd。
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # os.fdopen 接管 fd：正常退出由 with 关闭；仅当 fdopen 自身失败时才需手动 close。
    try:
        f = os.fdopen(fd, "w", encoding=encoding)
    except Exception:
        os.close(fd)
        raise
    with f:
        f.write(data)


def secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """创建目录并设置安全权限。"""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(str(path), mode)


# 凭证相关的 header 名（小写），日志中需脱敏
_SENSITIVE_HEADERS = {
    "authorization", "x-authtoken", "fdp-access", "fdp-secret",
    "x-api-key", "api-key", "cookie", "set-cookie", "proxy-authorization",
}


def redact_secrets(text: str) -> str:
    """对文本中的凭证片段做脱敏，用于日志输出。

    覆盖：header 形式（Authorization: xxx）、URL userinfo（https://user:pass@host）、
    常见 key/token 形式。仅做日志层防护，不影响实际请求。
    """
    import re
    if not text:
        return text
    # 1. URL userinfo: https://key:secret@host -> https://***@host
    text = re.sub(r"(https?://)[^@\s:/]+:[^@\s:/]+@", r"\1***@", text)
    # 2. header 形式: Authorization: Bearer xxx / X-AuthToken: xxx
    #    值可能含空格（如 "Bearer sk-xxx"），匹配到行尾或下一个 header/key=value 边界
    text = re.sub(
        r"((?:authorization|x-authtoken|fdp-access|fdp-secret|x-api-key|api-key|cookie)\s*[:=]\s*)([^\n\r]+)",
        r"\1***",
        text,
        flags=re.IGNORECASE,
    )
    return text

# 按目标类型分组的核心 MCP server
# 域名分析需要的 server
DOMAIN_SERVERS = {
    "ctia_domain", "ctia_ip", "qianxin_fdp_domain", "qianxin_fdp_ip",
    "qianxin_fdp", "hunter_mcp", "secagent",
}
# IP 分析需要的 server
IP_SERVERS = {
    "ctia_ip", "qianxin_fdp_ip", "qianxin_fdp", "iporg",
    "hunter_mcp", "secagent",
}
# 样本哈希分析需要的 server
HASH_SERVERS = {
    "qianxin_fdp_sample", "ctia_ip", "ctia_domain", "secagent",
}
# CVE 漏洞分析需要的 server
CVE_SERVERS = {
    "ctia_exploit", "ctia_ip", "secagent",
}
# 两种类型都需要的 server
COMMON_SERVERS = {
    "ctia_domain", "ctia_ip", "qianxin_fdp_domain", "qianxin_fdp_ip",
    "qianxin_fdp", "hunter_mcp", "secagent", "iporg",
}
# 核心安全 server（连接失败时需要告警）
CRITICAL_SERVERS = {
    "ctia_domain", "ctia_ip", "qianxin_fdp_domain", "qianxin_fdp_ip",
}
# 辅助 server（非安全分析核心，可选连接）
OPTIONAL_SERVERS = {
    "grep_app", "context7", "brave_search", "bocha_search",
}
# Exa 搜索（可选，通过 config 开关控制）
EXA_SERVER = "exa"


@dataclass
class LLMConfig:
    base_url: str = ""
    api_key: str = ""
    model: str = "deepseek-chat"
    temperature: float = 0.1
    max_tokens: int = 8192


@dataclass
class ModelRouter:
    """多模型路由：按分析深度选择模型。

    config.yaml 示例:
      models:
        fast: deepseek-chat        # quick 深度
        standard: deepseek-chat    # standard 深度
        reasoning: deepseek-reasoner  # deep 深度
    """
    fast: str = ""
    standard: str = ""
    reasoning: str = ""

    def select(self, depth: str, default_model: str = "") -> str:
        """根据深度选择模型。"""
        if depth == "quick" and self.fast:
            return self.fast
        if depth == "deep" and self.reasoning:
            return self.reasoning
        if depth == "standard" and self.standard:
            return self.standard
        return default_model


@dataclass
class MCPServerConfig:
    name: str
    url: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 120


@dataclass
class AgentConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    models: ModelRouter = field(default_factory=ModelRouter)
    mcp_servers: dict[str, MCPServerConfig] = field(default_factory=dict)
    max_iterations: int = 10
    timeout: int = 300
    secagent_home: Path = SECAGENT_HOME
    web_fetch_enabled: bool = True  # 内置 web_fetch 工具开关
    web_fetch_verify_ssl: bool = False  # web_fetch 是否验证 SSL 证书
    exa_enabled: bool = True        # Exa 搜索工具开关
    notify_webhooks: list[str] = field(default_factory=list)  # 告警 webhook URL
    notify_min_risk: str = ""      # 最低通知风险等级


def _load_dotenv(env_path: Path) -> dict[str, str]:
    """简易 .env 解析，不依赖 python-dotenv。"""
    envs: dict[str, str] = {}
    if not env_path.exists():
        return envs
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        envs[key] = value
    return envs


def _merge_env(defaults: dict[str, str]) -> dict[str, str]:
    """合并：os.environ > .env 文件 > 默认值。"""
    merged = dict(defaults)
    merged.update(os.environ)
    return merged


def _build_mcp_servers(
    yaml_servers: dict[str, Any],
    env: dict[str, str],
) -> dict[str, MCPServerConfig]:
    """从 YAML 和环境变量构建 MCP server 配置。"""
    result: dict[str, MCPServerConfig] = {}

    for name, raw in (yaml_servers or {}).items():
        conf = MCPServerConfig(name=name)
        if isinstance(raw, dict):
            conf.url = raw.get("url", "")
            conf.command = raw.get("command", "")
            conf.args = raw.get("args", [])
            conf.env = raw.get("env", {})
            conf.headers = raw.get("headers", {})
            conf.timeout = raw.get("timeout", 120)
        result[name] = conf

    # 注入认证 header（仅在 Hermes config 未提供时生效，setdefault 不覆盖已有值）
    # 使用与 Hermes config.yaml 一致的 header 名
    fdp_access_key = env.get("FDP_ACCESS_KEY", "")
    fdp_secret_key = env.get("FDP_SECRET_KEY", "")
    ctia_token = env.get("CTIA_TOKEN", "")
    hunter_token = env.get("MCP_HUNTER_MCP_API_KEY", "")

    for name, conf in result.items():
        if not conf.url:
            continue
        # 奇安信 FDP 系列（header 名: fdp-access, fdp-secret）
        if "fdp.qianxin.com" in conf.url and "ctia" not in name:
            if fdp_access_key and fdp_secret_key:
                conf.headers.setdefault("fdp-access", fdp_access_key)
                conf.headers.setdefault("fdp-secret", fdp_secret_key)
        # 奇安信 CTIA 系列（header 名: X-AuthToken）
        if "ctia" in name:
            if ctia_token:
                conf.headers.setdefault("X-AuthToken", ctia_token)
        # Hunter（header 名: Authorization）
        if "hunter" in name:
            if hunter_token:
                conf.headers.setdefault("Authorization", f"Bearer {hunter_token}")

    return result


def load_config(config_path: Path | None = None) -> AgentConfig:
    """加载配置，优先级：环境变量 > .env > config.yaml > 默认值。"""
    home = SECAGENT_HOME
    secure_mkdir(home)

    # 1. 加载 .env
    env_defaults: dict[str, str] = {}
    for p in [home / ".env", Path.home() / ".hermes" / ".env"]:
        env_defaults.update(_load_dotenv(p))
    env = _merge_env(env_defaults)

    # 2. 加载 config.yaml
    if config_path is None:
        config_path = home / "config.yaml"
    yaml_data: dict[str, Any] = {}
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f) or {}

    # 3. 构建 LLMConfig
    llm_raw = yaml_data.get("llm", {})
    llm = LLMConfig(
        base_url=env.get("SECAGENT_BASE_URL") or llm_raw.get("base_url", ""),
        api_key=env.get("SECAGENT_API_KEY") or llm_raw.get("api_key", ""),
        model=env.get("SECAGENT_MODEL") or llm_raw.get("model", "deepseek-chat"),
        temperature=llm_raw.get("temperature", 0.1),
        max_tokens=llm_raw.get("max_tokens", 8192),
    )

    # 4. 构建 MCP servers
    # 合并 Hermes 的 mcp_servers 配置（如果 secagent 自己没有）
    mcp_yaml = yaml_data.get("mcp_servers")
    if not mcp_yaml:
        hermes_cfg = Path.home() / ".hermes" / "config.yaml"
        if hermes_cfg.exists():
            with open(hermes_cfg, encoding="utf-8") as f:
                hermes_data = yaml.safe_load(f) or {}
            mcp_yaml = hermes_data.get("mcp_servers", {})

    mcp_servers = _build_mcp_servers(mcp_yaml, env)

    # 5. 多模型路由
    models_raw = yaml_data.get("models", {})
    models = ModelRouter(
        fast=models_raw.get("fast", ""),
        standard=models_raw.get("standard", ""),
        reasoning=models_raw.get("reasoning", ""),
    )

    # 6. Agent 参数
    agent_raw = yaml_data.get("agent", {})
    max_iter = agent_raw.get("max_iterations", 10)
    timeout = agent_raw.get("timeout", 300)

    # 7. web_fetch 开关
    wf_raw = yaml_data.get("web_fetch", {})
    web_fetch_enabled = wf_raw.get("enabled", True)
    web_fetch_verify_ssl = wf_raw.get("verify_ssl", False)

    # 8. Exa 搜索开关
    exa_enabled = yaml_data.get("exa", {}).get("enabled", True)

    # 9. 告警通知配置
    notify_raw = yaml_data.get("notify", {})
    notify_webhooks = [w.get("url", "") for w in (notify_raw.get("webhooks") or []) if w.get("url")]
    notify_min_risk = notify_raw.get("min_risk", "")

    return AgentConfig(
        llm=llm,
        models=models,
        mcp_servers=mcp_servers,
        max_iterations=max_iter,
        timeout=timeout,
        secagent_home=home,
        web_fetch_enabled=web_fetch_enabled,
        web_fetch_verify_ssl=web_fetch_verify_ssl,
        exa_enabled=exa_enabled,
        notify_webhooks=notify_webhooks,
        notify_min_risk=notify_min_risk,
    )


# ------------------------------------------------------------------
# 启动期配置校验
# ------------------------------------------------------------------

# 各类 server 需要的认证 header（小写）
_SERVER_REQUIRED_CREDS: dict[str, list[str]] = {
    "fdp": ["fdp-access", "fdp-secret"],   # 奇安信 FDP（非 ctia）
    "ctia": ["x-authtoken"],               # 奇安信 CTIA
    "hunter": ["authorization"],           # Hunter
    "exa": ["x-api-key"],                  # Exa
}


def _missing_credentials(name: str, conf: MCPServerConfig) -> list[str]:
    """检查 server 是否缺少必要认证凭证，返回缺失的 header 名列表。

    凭证可能来自 config.yaml 的 headers，也可能由 _build_mcp_servers 从
    环境变量注入；此处统一检查最终 headers 中的值是否非空。
    """
    headers = {k.lower(): (v or "") for k, v in conf.headers.items()}
    url = (conf.url or "").lower()
    required: list[str] = []

    if "fdp.qianxin.com" in url and "ctia" not in name:
        for h in _SERVER_REQUIRED_CREDS["fdp"]:
            if not headers.get(h):
                required.append(h)
    if "ctia" in name or "/ctia/" in url:
        for h in _SERVER_REQUIRED_CREDS["ctia"]:
            if not headers.get(h):
                required.append(h)
    if "hunter" in name:
        for h in _SERVER_REQUIRED_CREDS["hunter"]:
            if not headers.get(h):
                required.append(h)
    if "exa" in name:
        for h in _SERVER_REQUIRED_CREDS["exa"]:
            if not headers.get(h):
                required.append(h)
    return required


def validate_config(config: AgentConfig) -> tuple[list[str], list[str]]:
    """校验配置完整性，返回 (errors, warnings)。

    errors:   致命问题（如 LLM api_key 缺失），analyze/batch/serve 将无法正常工作
    warnings: 降级提示（如某 server 缺凭证），对应能力缺失但不阻止启动

    设计为只读校验、不抛异常，调用方据 (errors, warnings) 自行决定提示方式，
    以便 config show / --version 等命令仍可在配置不全时运行。
    """
    errors: list[str] = []
    warnings: list[str] = []

    # LLM 必填项
    if not config.llm.api_key:
        errors.append("LLM API key 未设置（llm.api_key 或环境变量 SECAGENT_API_KEY）")
    if not config.llm.base_url:
        errors.append("LLM base_url 未设置（llm.base_url 或环境变量 SECAGENT_BASE_URL）")
    if not config.llm.model:
        errors.append("LLM model 未设置（llm.model 或环境变量 SECAGENT_MODEL）")

    # MCP server 凭证：缺失则该 server 连接时会失败，对应情报能力缺失
    if not config.mcp_servers:
        warnings.append("未配置任何 MCP server，LLM 将仅基于自身知识分析")
    else:
        for name, conf in config.mcp_servers.items():
            if not conf.url and not conf.command:
                warnings.append(f"MCP server '{name}' 缺少 url/command，将被跳过")
                continue
            missing = _missing_credentials(name, conf)
            if missing:
                warnings.append(
                    f"MCP server '{name}' 缺少凭证 [{', '.join(missing)}]，"
                    f"该 server 将不可用"
                )

    return errors, warnings
