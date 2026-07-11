# secagent - CLI 安全分析 Agent

## 设计文档与实现规划

---

## 一、项目定位

secagent 是一个命令行安全分析 Agent。用户输入域名或 IP 地址，Agent 自主调用威胁情报、被动 DNS、资产发现等 MCP 工具链，综合判断目标是否存在安全风险。Agent 具备自我学习能力：从分析交互中积累经验，逐步优化分析策略。

核心设计原则：

- 轻量自包含：~25MB 依赖，pip install 即用，不绑定任何 Agent 框架
- 核心循环自建：OpenAI SDK tool calling 循环约 500 行，完全透明可控
- CLI 完全定制：argparse 子命令 + 交互式 REPL + 斜杠命令补全
- 自我学习自建：借鉴 Hermes 的三层模型（MEMORY.md + SKILL.md + SQLite FTS5），自己实现
- MCP 原生接入：使用官方 mcp 包，直接连接现有 FDP/CTIA/Hunter/iporg/secagent

---

## 二、技术栈

### 2.1 语言与运行时

| 项目 | 选择 | 理由 |
|------|------|------|
| 语言 | Python 3.11+ | MCP 官方 SDK、OpenAI SDK 均为 Python 一等公民；用户环境已有 3.11.15 |
| 包管理 | uv | 比 pip 快 10-100x，已有安装；支持 lockfile 保证可复现 |
| 虚拟环境 | venv | 标准库，无额外依赖 |

### 2.2 核心依赖（6 个直接依赖，~25MB）

| 包 | 版本 | 大小 | 用途 |
|----|------|------|------|
| openai | >=2.0 | 12 MB | LLM 调用 + tool calling（兼容 DeepSeek/GLM/OpenAI 等 OpenAI-compatible 端点） |
| mcp | >=1.0 | 2.2 MB | MCP 客户端（stdio + Streamable HTTP 传输） |
| rich | >=13.0 | 2.7 MB | CLI 格式化输出（表格、面板、Markdown 渲染） |
| prompt_toolkit | >=3.0 | 3.6 MB | 交互式 REPL（斜杠命令补全、历史记录、自动建议） |
| pyyaml | >=6.0 | 1 MB | 配置文件解析 |
| httpx | >=0.27 | 752 KB | HTTP 传输（已是 openai 的传递依赖） |

对比：Hermes Agent venv 380MB，本方案减少 94%。

### 2.3 标准库使用（无额外安装）

| 模块 | 用途 |
|------|------|
| sqlite3 (FTS5) | 会话存档全文索引 |
| asyncio | MCP 异步通信 |
| argparse | CLI 子命令解析 |
| json | 消息序列化 |
| re | 域名/IP 格式识别 |
| pathlib | 文件路径管理 |
| datetime | 时间戳 |

### 2.4 LLM 模型

| 优先级 | 模型 | 端点 | 用途 |
|--------|------|------|------|
| 首选 | deepseek-chat | https://api.deepseek.com/v1 | 主分析模型（性价比高，中文好） |
| 备选 | deepseek-reasoner | https://api.deepseek.com/v1 | 复杂推理（有 reasoning_content） |
| 备选 | glm-5-2-260617 | Ark.cn-beijing.volces.com | 当前 Hermes 使用的模型 |
| 可选 | 任意 OpenAI-compatible | - | 通过 config.yaml 配置 |

现有 .secagent/config.yaml 已配置 DeepSeek API，可直接使用。

---

## 三、MCP 工具链

以下 MCP server 已在 Hermes config.yaml 中配置并验证可用，secagent 直接复用：

### 3.1 安全分析核心工具（奇安信生态）

| MCP Server | URL | 工具数 | 用途 |
|------------|-----|--------|------|
| qianxin_fdp | fdp.qianxin.com/mcp/v1/basic/ | - | FDP 基础数据（综合查询） |
| qianxin_fdp_domain | fdp.qianxin.com/mcp/v1/domain/ | - | 域名 PDNS/WHOIS/TLS |
| qianxin_fdp_ip | fdp.qianxin.com/mcp/v1/ip/ | - | IP 归属/ASN |
| qianxin_fdp_sample | fdp.qianxin.com/mcp/v1/sample/ | - | 样本关联数据 |
| ctia_ip | fdp.qianxin.com/mcp/v1/ctia/ip/ | - | IP 威胁情报 |
| ctia_domain | fdp.qianxin.com/mcp/v1/ctia/domain/ | - | 域名威胁情报 |
| ctia_exploit | fdp.qianxin.com/mcp/v1/ctia/exploit/ | - | 漏洞利用情报 |
| ctia_c2_command | fdp.qianxin.com/mcp/v1/ctia/c2_command/ | - | C2 命令情报 |
| hunter_mcp | hunter.qianxin.com/mcp | - | 资产发现（IP/端口/域名搜索） |
| secagent | stdio (本地) | 12检测器+2LLM | 安全检测器 |
| iporg | mcp.grep.app | 5 | IP→组织归属 |

### 3.2 辅助工具（按需加载）

| MCP Server | 用途 |
|------------|------|
| bocha_search | 中文 Web 搜索 |
| brave_search | 英文 Web 搜索 |
| exa | Web 内容提取 |
| grep_app | 代码搜索 |
| context7 | 文档查询 |

### 3.3 认证

- FDP/CTIA：access_key + secret_key + ctia_token（已存于 ~/.secagent/config.yaml）
- Hunter：Bearer token（存于 .env 的 MCP_HUNTER_MCP_API_KEY）
- secagent：本地 stdio 进程，无需远程认证

---

## 四、架构设计

### 4.1 整体架构图

```
┌──────────────────────────────────────────────────────────┐
│                     用户交互层                             │
│                                                          │
│  ┌─────────────┐    ┌──────────────────────────────────┐│
│  │ CLI 子命令   │    │ 交互式 REPL                      ││
│  │ (argparse)  │    │ (prompt_toolkit)                 ││
│  │             │    │                                  ││
│  │ secagent    │    │ secagent> /analyze example.com   ││
│  │   analyze   │    │ secagent> example.com            ││
│  │   batch     │    │ secagent> /skills list           ││
│  │   skills    │    │ secagent> /memory show           ││
│  │   memory    │    │ secagent> /history search C2     ││
│  │   history   │    │                                  ││
│  │   config    │    │ 特性：斜杠补全/历史/自动建议       ││
│  └──────┬──────┘    └────────────┬─────────────────────┘│
│         └──────────┬─────────────┘                      │
│                    ▼                                    │
└──────────────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                   Agent 核心层                            │
│                 (agent.py, ~500行)                       │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │              分析循环 (analyze loop)              │    │
│  │                                                  │    │
│  │  1. 识别输入 (域名 vs IP)                         │    │
│  │  2. 加载相关技能 (SkillStore.find_relevant)       │    │
│  │  3. 构建系统提示 (persona + skills + memory)     │    │
│  │  4. 获取 MCP 工具定义 (MCPManager.get_tools)      │    │
│  │  5. while True:                                  │    │
│  │       response = llm.chat.completions.create(    │    │
│  │         messages, tools=tool_defs                │    │
│  │       )                                          │    │
│  │       if not response.tool_calls: break          │    │
│  │       for tc in response.tool_calls:             │    │
│  │         result = await mcp.call_tool(tc)         │    │
│  │         messages.append(tool_result)             │    │
│  │  6. 解析最终结果 → AnalysisResult                 │    │
│  │  7. 事后学习 (_post_analyze_learning)            │    │
│  └──────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────┐  ┌────────────────────────────┐     │
│  │ 提示构建器        │  │ 结果解析器                  │     │
│  │ (prompt_builder) │  │ (result_parser)            │     │
│  │                  │  │                            │     │
│  │ - persona        │  │ - 风险等级提取              │     │
│  │ - 技能注入       │  │ - IOC 列表提取              │     │
│  │ - 记忆注入       │  │ - 结构化输出                │     │
│  │ - 工具描述       │  │ - 报告生成                  │     │
│  └─────────────────┘  └────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────────┐    ┌──────────────────────────────┐
│   MCP 工具层         │    │       自我学习层              │
│  (mcp_manager.py)   │    │     (learning.py)            │
│                     │    │                              │
│  Streamable HTTP:   │    │  ┌──────────────────────┐    │
│  ├─ ctia_ip         │    │  │ MemoryStore          │    │
│  ├─ ctia_domain     │    │  │ (MEMORY.md)          │    │
│  ├─ ctia_exploit    │    │  │ 上限 2200 字符        │    │
│  ├─ ctia_c2_command │    │  │ LLM 辅助压缩          │    │
│  ├─ fdp_domain      │    │  └──────────────────────┘    │
│  ├─ fdp_ip          │    │  ┌──────────────────────┐    │
│  ├─ fdp_sample      │    │  │ SkillStore           │    │
│  ├─ hunter_mcp      │    │  │ (SKILL.md 目录)      │    │
│  └─ iporg           │    │  │ 相关技能匹配          │    │
│                     │    │  │ 技能创建/更新         │    │
│  Stdio:             │    │  └──────────────────────┘    │
│  └─ secagent        │    │  ┌──────────────────────┐    │
│                     │    │  │ SessionDB            │    │
│  功能：              │    │  │ (SQLite FTS5)        │    │
│  - 连接池管理        │    │  │ 全文检索历史会话      │    │
│  - 工具发现          │    │  └──────────────────────┘    │
│  - 并行调用          │    │  ┌──────────────────────┐    │
│  - 超时/重试         │    │  │ LearningTrigger      │    │
│  - 错误降级          │    │  │ 事后评估+技能创建触发  │    │
│                     │    │  └──────────────────────┘    │
└─────────────────────┘    └──────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│                    存储层                                 │
│                                                          │
│  ~/.secagent/                                            │
│  ├── config.yaml          配置文件                       │
│  ├── MEMORY.md            持久记忆（跨会话稳定事实）       │
│  ├── sessions.db          SQLite FTS5 会话存档            │
│  ├── cli_history          命令行历史                     │
│  ├── skills/              技能库                         │
│  │   ├── domain-security-analysis/SKILL.md               │
│  │   ├── ip-security-analysis/SKILL.md                   │
│  │   └── dga-domain-detection/SKILL.md                   │
│  └── logs/                运行日志                       │
└──────────────────────────────────────────────────────────┘
```

### 4.2 目录结构

```
secagent/
├── secagent/
│   ├── __init__.py
│   ├── __main__.py          # python -m secagent 入口
│   ├── cli.py               # CLI 解析 + 交互式 REPL (~300行)
│   ├── agent.py             # 核心分析循环 (~500行)
│   ├── mcp_manager.py       # MCP 客户端管理 (~300行)
│   ├── learning.py          # 自我学习层 (~400行)
│   │   ├── MemoryStore      #   MEMORY.md 读写
│   │   ├── SkillStore       #   SKILL.md 管理
│   │   ├── SessionDB        #   SQLite FTS5
│   │   └── LearningTrigger  #   学习触发逻辑
│   ├── prompt_builder.py    # 系统提示构建 (~150行)
│   ├── result_parser.py     # 结果解析与报告 (~200行)
│   ├── config.py            # 配置加载 (~100行)
│   └── utils.py             # 工具函数 (~50行)
├── skills/                  # 预置技能
│   ├── domain-security-analysis/
│   │   └── SKILL.md
│   ├── ip-security-analysis/
│   │   └── SKILL.md
│   └── threat-intel-correlation/
│       └── SKILL.md
├── tests/
│   ├── test_agent.py
│   ├── test_mcp_manager.py
│   ├── test_learning.py
│   └── test_cli.py
├── pyproject.toml           # 项目元数据 + 依赖
├── uv.lock                  # 锁定依赖版本
├── README.md
└── install.sh               # 一键安装脚本
```

预计总代码量：~2000-2500 行 Python（不含测试）。

---

## 五、核心模块详细设计

### 5.1 agent.py - 核心分析循环

```python
class SecurityAgent:
    """安全分析 Agent 核心"""
    
    def __init__(self, config: AgentConfig):
        self.llm_client = OpenAI(
            base_url=config.llm_base_url,
            api_key=config.llm_api_key,
        )
        self.model = config.llm_model
        self.mcp = MCPManager(config.mcp_servers)
        self.memory = MemoryStore(config.secagent_home)
        self.skills = SkillStore(config.secagent_home)
        self.sessions = SessionDB(config.secagent_home)
        self.max_iterations = config.max_iterations  # 默认 10
        
    async def analyze(self, target: str, depth: str = "standard") -> AnalysisResult:
        """分析域名或 IP"""
        # 1. 识别目标类型
        target_type = "ip" if is_valid_ip(target) else "domain"
        
        # 2. 加载相关技能
        relevant_skills = self.skills.find_relevant(target_type, target)
        
        # 3. 构建系统提示
        system_prompt = build_system_prompt(
            persona=SECURITY_ANALYST_PERSONA,
            skills=relevant_skills,
            memory=self.memory.get_context(),
            target=target,
            target_type=target_type,
            depth=depth,
        )
        
        # 4. 获取工具定义
        tool_defs = await self.mcp.get_tool_definitions()
        
        # 5. Agent 循环
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"分析目标: {target}"},
        ]
        
        tools_used = []
        raw_tool_outputs = []
        
        for i in range(self.max_iterations):
            response = self.llm_client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tool_defs,
                temperature=0.1,  # 分析场景用低温度
            )
            
            msg = response.choices[0].message
            messages.append(msg.model_dump())
            
            if not msg.tool_calls:
                # 最终分析结果
                break
            
            # 并行执行工具调用
            results = await asyncio.gather(*[
                self.mcp.call_tool(tc.function.name, 
                                   json.loads(tc.function.arguments))
                for tc in msg.tool_calls
            ], return_exceptions=True)
            
            for tc, result in zip(msg.tool_calls, results):
                tool_name = tc.function.name
                tools_used.append(tool_name)
                if isinstance(result, Exception):
                    content = f"工具调用失败: {result}"
                else:
                    content = json.dumps(result, ensure_ascii=False)
                    raw_tool_outputs.append({"tool": tool_name, 
                                            "args": tc.function.arguments,
                                            "result": result})
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })
        
        # 6. 解析结果
        result = parse_analysis_result(
            target=target,
            target_type=target_type,
            llm_output=msg.content,
            tools_used=tools_used,
            raw_outputs=raw_tool_outputs,
        )
        
        # 7. 事后学习
        await self._post_analyze_learning(target, result, messages)
        
        # 8. 存档会话
        self.sessions.save(target, result.summary, messages)
        
        return result
    
    async def _post_analyze_learning(self, target, result, messages):
        """事后学习：评估是否需要更新记忆或创建技能"""
        # 复杂度评估
        complexity = len(result.tools_used)
        
        if complexity >= 8:
            # 复杂分析，可能值得创建技能
            should_create = self.skills.should_create_skill(result, messages)
            if should_create:
                # 提示用户确认（交互式模式）或自动创建（批处理模式）
                skill_content = await self._extract_skill(target, result, messages)
                self.skills.create_skill(
                    name=derive_skill_name(result),
                    content=skill_content,
                    trigger=result.target_type,
                )
        
        # 更新记忆
        if result.notable_patterns:
            for pattern in result.notable_patterns:
                self.memory.add(pattern)
```

### 5.2 mcp_manager.py - MCP 客户端管理

```python
class MCPManager:
    """管理多个 MCP server 连接"""
    
    def __init__(self, servers_config: dict):
        self.servers_config = servers_config
        self.sessions: dict[str, ClientSession] = {}
        self.tools_cache: list[MCPTool] = []
    
    async def connect_all(self):
        """连接所有配置的 MCP server"""
        tasks = []
        for name, conf in self.servers_config.items():
            if conf.get("url"):
                tasks.append(self._connect_http(name, conf))
            elif conf.get("command"):
                tasks.append(self._connect_stdio(name, conf))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for name, result in zip(self.servers_config.keys(), results):
            if isinstance(result, Exception):
                logger.warning(f"MCP server {name} 连接失败: {result}")
            else:
                logger.info(f"MCP server {name} 已连接")
        
        # 发现所有工具
        await self._discover_tools()
    
    async def _connect_http(self, name: str, conf: dict):
        """连接 Streamable HTTP MCP server"""
        from mcp.client.streamable_http import streamablehttp_client
        
        headers = conf.get("headers", {})
        # 注入认证信息
        if name.startswith("ctia") or name.startswith("fdp"):
            headers["X-FDP-Key"] = self._get_fdp_auth(conf)
        elif name == "hunter_mcp":
            headers["Authorization"] = f"Bearer {self._get_hunter_token()}"
        
        async with streamablehttp_client(conf["url"], headers=headers) as (read, write, _):
            session = ClientSession(read, write)
            await session.initialize()
            self.sessions[name] = session
    
    async def _connect_stdio(self, name: str, conf: dict):
        """连接 stdio MCP server"""
        from mcp.client.stdio import stdio_client, StdioServerParameters
        
        params = StdioServerParameters(
            command=conf["command"],
            args=conf.get("args", []),
            env=conf.get("env", {}),
        )
        async with stdio_client(params) as (read, write):
            session = ClientSession(read, write)
            await session.initialize()
            self.sessions[name] = session
    
    async def _discover_tools(self):
        """发现所有 server 的工具"""
        self.tools_cache = []
        for name, session in self.sessions.items():
            result = await session.list_tools()
            for tool in result.tools:
                self.tools_cache.append(MCPTool(
                    server=name,
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.inputSchema,
                ))
    
    async def get_tool_definitions(self) -> list[dict]:
        """返回 OpenAI tool calling 格式的工具定义"""
        return [
            {
                "type": "function",
                "function": {
                    "name": f"{t.server}__{t.name}",
                    "description": t.description,
                    "parameters": t.input_schema,
                }
            }
            for t in self.tools_cache
        ]
    
    async def call_tool(self, full_name: str, args: dict) -> Any:
        """调用 MCP 工具"""
        server_name, tool_name = full_name.split("__", 1)
        session = self.sessions.get(server_name)
        if not session:
            raise MCPError(f"Server {server_name} 未连接")
        
        result = await asyncio.wait_for(
            session.call_tool(tool_name, args),
            timeout=120,
        )
        return self._extract_content(result)
```

### 5.3 learning.py - 自我学习层

```python
class MemoryStore:
    """持久记忆 - 跨会话的稳定事实"""
    
    MEMORY_LIMIT = 2200  # 字符上限
    
    def __init__(self, home: Path):
        self.memory_file = home / "MEMORY.md"
        self.llm_client = None  # 延迟初始化，用于压缩
        self.content = self._load()
    
    def _load(self) -> str:
        if self.memory_file.exists():
            return self.memory_file.read_text(encoding="utf-8")
        return ""
    
    def _save(self):
        self.memory_file.write_text(self.content, encoding="utf-8")
    
    def add(self, fact: str):
        """添加稳定事实"""
        if fact in self.content:
            return
        self.content = (self.content + "\n" + fact).strip()
        if len(self.content) > self.MEMORY_LIMIT:
            self._compress()
        self._save()
    
    def get_context(self) -> str:
        """返回记忆内容，注入系统提示"""
        return self.content
    
    def _compress(self):
        """LLM 辅助压缩：合并重复、删除过时"""
        # 调用 LLM 压缩到限制内
        prompt = f"压缩以下记忆，保留关键信息，删除重复和过时内容，不超过 {self.MEMORY_LIMIT} 字符:\n{self.content}"
        self.content = llm_compress(prompt, self.llm_client)[:self.MEMORY_LIMIT]


class SkillStore:
    """技能存储 - 可复用的分析方法"""
    
    def __init__(self, home: Path, builtin_skills_dir: Path = None):
        self.skills_dir = home / "skills"
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.builtin_dir = builtin_skills_dir  # 包内置技能
    
    def find_relevant(self, context: str, target: str = "") -> list[Skill]:
        """匹配相关技能"""
        all_skills = self._load_all()
        relevant = []
        for skill in all_skills:
            trigger = skill.trigger.lower()
            ctx = (context + " " + target).lower()
            if trigger in ctx or any(kw in ctx for kw in trigger.split()):
                relevant.append(skill)
        return relevant
    
    def should_create_skill(self, result, messages) -> bool:
        """评估是否值得创建技能"""
        # 启发式规则
        if len(result.tools_used) < 8:
            return False
        if not result.notable_patterns:
            return False
        # 检查是否与现有技能重复
        existing = self._load_all()
        for s in existing:
            if s.trigger == result.target_type:
                return False
        return True
    
    def create_skill(self, name: str, content: str, trigger: str):
        skill_path = self.skills_dir / name / "SKILL.md"
        skill_path.parent.mkdir(parents=True, exist_ok=True)
        skill_path.write_text(
            f"---\nname: {name}\ntrigger: {trigger}\n"
            f"created: {datetime.now().isoformat()}\n---\n{content}",
            encoding="utf-8",
        )


class SessionDB:
    """会话存档 - SQLite FTS5"""
    
    def __init__(self, home: Path):
        self.db_path = home / "sessions.db"
        self.db = sqlite3.connect(str(self.db_path))
        self.db.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS sessions USING fts5(
                target, summary, messages, timestamp
            )
        """)
        self.db.commit()
    
    def save(self, target: str, summary: str, messages: list):
        self.db.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?)",
            (target, summary, json.dumps(messages, ensure_ascii=False),
             datetime.now().isoformat())
        )
        self.db.commit()
    
    def search(self, query: str, limit: int = 10) -> list:
        cursor = self.db.execute(
            "SELECT target, summary, timestamp FROM sessions "
            "WHERE sessions MATCH ? ORDER BY timestamp DESC LIMIT ?",
            (query, limit)
        )
        return cursor.fetchall()


class LearningTrigger:
    """学习触发逻辑"""
    
    def __init__(self, memory: MemoryStore, skills: SkillStore):
        self.memory = memory
        self.skills = skills
    
    async def evaluate(self, target, result, messages, interactive=True):
        """分析后评估"""
        # 1. 记忆更新
        if result.misinfo_patterns:
            # 误报模式：记录到记忆
            for pattern in result.misinfo_patterns:
                self.memory.add(f"误报模式: {pattern}")
        
        if result.strategy_corrections:
            for correction in result.strategy_corrections:
                self.memory.add(f"分析策略: {correction}")
        
        # 2. 技能创建
        if self.skills.should_create_skill(result, messages):
            if interactive:
                # 交互式：提示用户确认
                print(f"\n本次分析较复杂({len(result.tools_used)}个工具调用)，"
                      f"是否创建可复用技能？(y/n)")
                if input().strip().lower() == 'y':
                    skill_content = await self._extract_skill(result, messages)
                    self.skills.create_skill(
                        name=derive_skill_name(result),
                        content=skill_content,
                        trigger=result.target_type,
                    )
            else:
                # 批处理：自动创建
                skill_content = await self._extract_skill(result, messages)
                self.skills.create_skill(
                    name=derive_skill_name(result),
                    content=skill_content,
                    trigger=result.target_type,
                )
```

### 5.4 cli.py - 命令行界面

#### 子命令模式

```bash
# 单次分析
secagent analyze example.com
secagent analyze 1.2.3.4 --format json --depth deep

# 批量分析
secagent batch targets.txt --output report.json

# 技能管理
secagent skills list
secagent skills show domain-security-analysis
secagent skills create custom-dga-check

# 记忆管理
secagent memory show
secagent memory add "某CDN IP段频繁误报"
secagent memory search "C2"

# 历史搜索
secagent history search "phishing"
secagent history list --limit 20

# 配置
secagent config show
secagent config set model deepseek-reasoner

# 交互式模式（默认）
secagent
```

#### 交互式 REPL

```
secagent> /analyze example.com          # 斜杠命令
secagent> example.com                    # 直接输入目标
secagent> /skills list                   # 技能列表
secagent> /memory add 用户偏好           # 添加记忆
secagent> /history search C2            # 搜索历史
secagent> /config model deepseek-chat   # 切换模型
secagent> /help                          # 帮助
secagent> /exit                          # 退出
```

特性：
- 斜杠命令补全（NestedCompleter，输入 /s 自动提示 /skills）
- 子命令补全（输入 /skills 后自动提示 list/show/create/delete）
- 历史记录（上下箭头，持久化到 cli_history）
- 自动建议（灰色文字，基于历史）
- Rich 格式化输出（表格、面板、Markdown）

### 5.5 prompt_builder.py - 系统提示构建

```python
SECURITY_ANALYST_PERSONA = """你是一个域名/IP 安全分析 Agent。
用户输入域名或 IP 地址时，你需要：
1. 识别输入类型（域名 vs IP）
2. 按标准流程执行安全分析
3. 调用 MCP 工具收集威胁情报、被动DNS、资产信息
4. 综合判断安全风险等级（低/中/高/严重）
5. 输出结构化分析报告

分析原则：
- 事实与推断分离：明确标注哪些是工具返回的客观事实，哪些是分析推断
- 多源交叉验证：单一来源的结论标注为"待验证"
- 向上追溯：分析完 FQDN 后向上追溯父域名
- 不遗漏步骤：按技能中定义的流程执行每一步

输出格式：
分析完成后，用以下 JSON 格式输出最终结论：
```json
{
  "risk_level": "低|中|高|严重",
  "confidence": 0.0-1.0,
  "findings": ["发现1", "发现2"],
  "iocs": ["恶意IP", "恶意域名"],
  "tools_used": ["工具名"],
  "summary": "一句话摘要",
  "recommendation": "处置建议"
}
```
"""

def build_system_prompt(persona, skills, memory, target, target_type, depth):
    parts = [persona]
    
    if memory:
        parts.append(f"\n--- 持久记忆 ---\n{memory}")
    
    if skills:
        parts.append("\n--- 相关技能 ---")
        for skill in skills:
            parts.append(f"\n## 技能: {skill.name}\n触发: {skill.trigger}\n{skill.content}")
    
    parts.append(f"\n--- 当前任务 ---")
    parts.append(f"目标: {target}")
    parts.append(f"类型: {target_type}")
    parts.append(f"分析深度: {depth}")
    
    return "\n".join(parts)
```

---

## 六、预置技能

### 6.1 domain-security-analysis

```markdown
---
name: domain-security-analysis
trigger: domain
---

## 域名安全分析标准流程

1. CTIA 域名威胁情报查询
   - 调用 ctia_domain 查询威胁标签（C2/钓鱼/恶意软件分发等）
   
2. FDP 域名基础数据查询
   - 调用 fdp_domain 查询 PDNS 解析记录
   - 查询 WHOIS 注册信息（注册时间、注册商、注册人）
   - 查询 TLS 证书信息
   
3. 浏览器访问验证
   - 访问域名查看实际 Web 内容
   - 检查是否为钓鱼页面、挂马站点
   
4. Hunter 资产搜索
   - 搜索同 IP 的其他域名
   - 搜索同 ASN 的其他资产
   
5. 向上追溯父域名
   - 逐级追溯父域名（特别是 .cn 行政区划域名）
   - 检查父域名是否也有安全风险

6. 风险评分
   - 综合威胁标签、基础设施特征、行为模式
   - CDN/WAF IP 需降低风险评分
```

### 6.2 ip-security-analysis

```markdown
---
name: ip-security-analysis
trigger: ip
---

## IP 安全分析标准流程

1. CTIA IP 威胁情报查询
   - 调用 ctia_ip 查询威胁标签
   
2. FDP IP 归属查询
   - 调用 fdp_ip 查询归属组织、ASN
   - 调用 iporg 精确查询 IP→组织映射
   
3. 反向 DNS 查询
   - 通过 FDP PDNS 查询反向解析记录
   
4. 开放端口推断
   - 通过 Hunter 搜索该 IP 的开放端口
   
5. 关联域名查询
   - 查询解析到该 IP 的域名列表
   
6. 风险评分
   - 知名 CDN/WAF 的 IP 降低风险
   - 独立服务器且关联恶意域名则提高风险
```

### 6.3 threat-intel-correlation

```markdown
---
name: threat-intel-correlation
trigger: correlation
---

## 多源情报交叉关联分析

1. 汇总各工具返回的威胁标签
2. 检查标签一致性（多源一致 → 高置信度）
3. 关联查询：
   - 域名 → 解析IP → IP威胁情报 → 同ASN资产
   - IP → 反向DNS → 域名威胁情报 → 父域名
4. 时间线分析：注册时间、首次发现时间、最近活跃时间
5. 输出关联图谱
```

---

## 七、自我学习机制

### 7.1 三层学习模型

```
                    分析完成
                       │
                       ▼
              ┌────────────────┐
              │  LearningTrigger │
              │   .evaluate()    │
              └───────┬────────┘
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
    第一层         第二层         第三层
    MEMORY.md    SKILL.md      SQLite FTS5
    (记忆)       (技能)        (会话存档)
    
    存储内容：    存储内容：     存储内容：
    - 分析偏好    - 分析方法    - 完整消息
    - 误报模式    - 触发条件    - 目标+摘要
    - 策略修正    - 步骤文档    - 时间戳
    
    生命周期：    生命周期：     生命周期：
    持久(有上限)  持久(可删除)   持久(可清理)
    2200字符     无上限         无上限
    LLM压缩      用户确认创建   自动存档
    
    注入方式：    注入方式：     检索方式：
    系统提示      技能匹配后     FTS5全文搜索
    每次自动注入  按需注入       按需搜索
```

### 7.2 学习触发条件

| 条件 | 动作 | 示例 |
|------|------|------|
| 工具调用 > 8 次 + 发现新模式 | 提示创建技能 | 复杂 C2 基础设施分析 |
| 发现误报 | 更新记忆 | CDN IP 被 CTIA 标记但实际安全 |
| 用户纠正分析结论 | 更新记忆+策略 | "这个不是钓鱼，是合法 CDN" |
| 每次分析完成 | 存档会话 | 自动存入 SQLite |
| 用户手动添加 | 更新记忆 | /memory add "某 ASN 需要特别关注" |

### 7.3 学习安全控制

- 技能创建需用户确认（交互式模式）
- 记忆有 2200 字符上限，超限自动 LLM 压缩
- 技能可手动删除（/skills delete）
- 记忆可手动清理（/memory clear）
- 历史可手动清理（/history clear）
- 所有学习产物都是纯文本文件，可审查、可编辑

---

## 八、风险评分模型

```
风险评分 = f(威胁标签, 基础设施可信度, 行为模式)

威胁标签权重：
  C2 服务器:        0.9
  恶意软件分发:      0.8
  钓鱼站点:         0.7
  僵尸网络节点:      0.8
  代理/匿名服务:    0.4
  扫描器:           0.5

基础设施可信度（降低风险评分）：
  知名CDN/WAF:      0.3  (Cloudflare/Akamai/AWS WAF)
  云服务商:          0.5  (AWS/GCP/Azure)
  共享主机:          0.7
  独立服务器:        0.9
  历史干净:          0.6

行为模式系数：
  首次发现:          1.0
  24h内活跃:         1.2
  关联已知恶意:       1.5
  多源情报一致:       1.3

最终评分 = max(威胁标签权重) × 基础设施可信度 × 行为模式系数

评分映射：
  0.0 - 0.2  →  低
  0.2 - 0.5  →  中
  0.5 - 0.8  →  高
  0.8 - 1.0  →  严重
```

---

## 九、依赖关系

### 9.1 模块依赖图

```
cli.py
 ├── agent.py
 │    ├── mcp_manager.py  → mcp (PyPI)
 │    ├── learning.py
 │    │    ├── MemoryStore  → MEMORY.md (文件)
 │    │    ├── SkillStore   → SKILL.md (文件)
 │    │    ├── SessionDB    → sqlite3 (stdlib)
 │    │    └── LearningTrigger
 │    ├── prompt_builder.py
 │    ├── result_parser.py
 │    └── config.py        → pyyaml (PyPI)
 ├── rich (PyPI)           → 输出格式化
 └── prompt_toolkit (PyPI) → REPL 交互
```

### 9.2 外部依赖

```
secagent
 ├── LLM API (DeepSeek/OpenAI/GLM)
 │    └── openai SDK
 │
 ├── MCP Servers
 │    ├── FDP/CTIA (fdp.qianxin.com)  → httpx
 │    ├── Hunter (hunter.qianxin.com)  → httpx
 │    ├── iporg (mcp.grep.app)         → httpx
 │    └── secagent (local stdio)       → subprocess
 │
 └── 本地存储
      ├── MEMORY.md    → pathlib
      ├── SKILL.md     → pathlib
      └── sessions.db  → sqlite3
```

### 9.3 pyproject.toml

```toml
[project]
name = "secagent"
version = "0.1.0"
description = "CLI 安全分析 Agent - 域名/IP 安全风险判断"
requires-python = ">=3.11"
dependencies = [
    "openai>=2.0",
    "mcp>=1.0",
    "rich>=13.0",
    "prompt_toolkit>=3.0",
    "pyyaml>=6.0",
    "httpx>=0.27",
]

[project.scripts]
secagent = "secagent.cli:main"

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"
```

---

## 十、实现规划

### 阶段 1：核心循环 MVP（1 周）

目标：验证"OpenAI SDK + MCP + 自写循环"能完成安全分析

| 任务 | 文件 | 预估行数 | 验证标准 |
|------|------|---------|---------|
| 项目脚手架 | pyproject.toml, __init__.py | - | uv install 可用 |
| 配置加载 | config.py | ~100 | 读取 config.yaml + 环境变量 |
| MCP 客户端管理 | mcp_manager.py | ~300 | 连接 FDP/CTIA，发现工具 |
| 核心分析循环 | agent.py | ~500 | 分析 5 域名 + 5 IP |
| 提示构建器 | prompt_builder.py | ~150 | persona + 工具描述注入 |
| 结果解析器 | result_parser.py | ~200 | JSON 输出 + 风险等级 |
| CLI 基本功能 | cli.py | ~200 | analyze 子命令 |

里程碑：`secagent analyze example.com` 输出完整分析结果

### 阶段 2：学习层（1-2 周）

目标：自我学习闭环在安全分析场景可行

| 任务 | 文件 | 预估行数 | 验证标准 |
|------|------|---------|---------|
| 持久记忆 | learning.py (MemoryStore) | ~100 | MEMORY.md 读写 + LLM 压缩 |
| 技能存储 | learning.py (SkillStore) | ~150 | SKILL.md 管理 + 相关匹配 |
| 会话存档 | learning.py (SessionDB) | ~50 | SQLite FTS5 存档 + 搜索 |
| 学习触发 | learning.py (LearningTrigger) | ~100 | 事后评估 + 技能创建 |
| 预置技能 | skills/*.SKILL.md | ~300 | 3 个核心技能文档 |
| CLI 扩展 | cli.py 扩展 | ~100 | /skills /memory /history 命令 |

里程碑：分析 20 个目标后，Agent 创建了至少 1 个有效技能

### 阶段 3：交互式 REPL + 产品化（2 周）

目标：可用的产品级 CLI 工具

| 任务 | 文件 | 预估行数 | 验证标准 |
|------|------|---------|---------|
| 交互式 REPL | cli.py 扩展 | ~200 | 斜杠补全/历史/自动建议 |
| 批量分析 | cli.py 扩展 | ~80 | targets.txt 批处理 |
| 报告导出 | result_parser.py 扩展 | ~100 | JSON/Markdown/文本输出 |
| 风险评分模型 | result_parser.py 扩展 | ~80 | 评分计算 + 等级映射 |
| 错误处理 | 全模块 | ~100 | 超时/重试/降级 |
| 安装脚本 | install.sh | ~30 | 一键安装 |
| 文档 | README.md | ~200 | 安装/使用/配置说明 |

里程碑：非技术人员可按文档安装使用

### 阶段 4：进阶能力（持续迭代）

| 任务 | 说明 | 优先级 |
|------|------|--------|
| 定时监控 | cron job 监控目标变化 | P1 |
| 多模型路由 | 简单查询用小模型，复杂分析用大模型 | P1 |
| 分析策略 A/B | 对比不同分析策略的效果 | P2 |
| Web UI | 可选的 Web 界面 | P3 |
| 多用户支持 | 共享技能库 + 独立记忆 | P3 |

---

## 十一、与 Hermes 的关系

| 维度 | secagent | Hermes Agent |
|------|---------|-------------|
| 定位 | 安全分析专用 CLI | 通用 AI Agent |
| 体积 | ~25MB / ~2500行 | 380MB / ~50万行 |
| MCP | 原生 mcp 包 | 原生（内置） |
| 自我学习 | 自建三层模型 | 原生（成熟） |
| CLI | 完全定制 | 通用 REPL |
| 移植 | pip install | 完整运行时 |
| 关系 | 独立项目 | 可选参考 |

secagent 不依赖 Hermes，但：
- 复用 Hermes 已配置的 MCP server（相同 URL 和认证）
- 借鉴 Hermes 的自我学习设计模型（MEMORY.md / SKILL.md / SQLite FTS5）
- 可选：通过 /skills export 导出技能到 Hermes 兼容格式

---

## 十二、文件清单

```
~/secagent/
├── secagent/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py               # REPL + 子命令
│   ├── agent.py             # 核心循环
│   ├── mcp_manager.py       # MCP 客户端
│   ├── learning.py          # 自我学习
│   ├── prompt_builder.py    # 提示构建
│   ├── result_parser.py     # 结果解析
│   ├── config.py            # 配置管理
│   └── utils.py             # 工具函数
├── skills/
│   ├── domain-security-analysis/SKILL.md
│   ├── ip-security-analysis/SKILL.md
│   └── threat-intel-correlation/SKILL.md
├── tests/
│   ├── test_agent.py
│   ├── test_mcp_manager.py
│   ├── test_learning.py
│   └── test_cli.py
├── pyproject.toml
├── uv.lock
├── README.md
└── install.sh

~/.secagent/
├── config.yaml              # 用户配置
├── MEMORY.md                # 持久记忆
├── sessions.db              # 会话存档
├── cli_history              # 命令历史
├── skills/                  # 自动创建的技能
└── logs/                    # 运行日志
```

预计总代码量：~2500 行 Python（不含测试和技能文档）
预计依赖体积：~25MB
预计 MVP 周期：1 周（核心循环）+ 1-2 周（学习层）+ 2 周（产品化）= 4-5 周
