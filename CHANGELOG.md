# secagent 开发日志

## 项目背景

目标：构建一个轻量、可移植的 CLI 安全分析 Agent，输入域名/IP/哈希/CVE，自主调用 MCP 工具链判断安全风险，具备自我学习能力。

核心约束：不依赖 Hermes 框架运行时（380MB），追求轻量（~25MB 依赖）和可移植性。

---

## 阶段一：框架选型与设计（v0.1.0 前期）

### 框架调研
- 调研了 Hermes Agent、LangGraph、PydanticAI、AutoGen、smolagents、CrewAI 等开源框架
- 结论：Hermes 在自我学习上最优但过于庞大（380MB venv、50 万行代码），不适合轻量部署
- 决策：自建轻量核心，借鉴 Hermes 的三层学习模型，但完全自控

### 设计文档
- 输出完整设计文档 `DESIGN.md`（1112 行），定义架构、技术栈、依赖、模块、文件清单
- 技术栈：Python 3.11+, OpenAI SDK, MCP 官方包, Rich, prompt_toolkit, PyYAML, httpx
- 依赖总量 ~25MB

---

## 阶段二：核心实现（v0.1.0）

### 模块实现顺序
1. `config.py` — YAML + 环境变量 + .env 配置加载
2. `mcp_manager.py` — MCP 连接池、工具发现与调用（HTTP + stdio 两种传输）
3. `prompt_builder.py` — 系统提示构建（persona + skills + memory + task）
4. `result_parser.py` — 结果解析与风险评分
5. `learning.py` — MemoryStore + SkillStore + SessionDB
6. `agent.py` — 核心分析循环（OpenAI SDK tool calling）
7. `cli.py` — argparse 子命令 + 交互式 REPL

### 预置技能
- domain-security-analysis（域名分析 SOP）
- ip-security-analysis（IP 分析流程）
- threat-intel-correlation（多源交叉验证）

### 关键技术决策
- MCP 连接管理：所有 session 在同一 async task 中创建/销毁，避免 anyio "cancel scope in different task" 错误
- 配置加载：优先 secagent 自己的 config.yaml，fallback 到 Hermes 的 config.yaml
- Header 注入：使用与 Hermes config.yaml 一致的 header 名（fdp-access、X-AuthToken、Authorization）

---

## 阶段三：产品化改进（v0.1.0 后期）

### P0 修复
- config.py header 注入修正（X-FDP-Access-Key → fdp-access 等）
- MEMORY.md 压缩（31 条重复记录 → 8 条精炼规则，节省 80% token）
- SessionDB 持久化修复（移除破坏性的 DROP TABLE）

### P1 工程质量
- 补测试覆盖：web_fetch.py + compare.py（+16 个测试）
- web_fetch verify_ssl 配置开关（默认 False，安全分析场景需要看自签证书站点）
- README.md 编写

### P2 进阶能力
- install.sh 一键安装脚本
- 多模型路由（quick → chat，deep → reasoner）
- 定时监控（monitor add/list/run/history）
- 策略 A/B 对比（compare）
- pytest 测试套件（77 个测试）

---

## 阶段四：功能增强

### 多轮追问
- agent.py 新增 `ask()` 方法，复用 MCP 连接和对话历史
- `_AsyncLoopRunner` 后台事件循环，保持连接跨轮次存活
- REPL 自动切换提示符 `secagent(target)>`，/end 结束会话

### 思考过程展示
- `_run_loop` 新增 `on_thinking` 回调
- 支持 DeepSeek Reasoner 的 `reasoning_content`
- CLI 用 💭 图标展示中间推理

### 日志抑制
- 用 logging filter 拦截 MCP/httpx INFO 级别日志
- `--verbose` 时恢复完整日志

### 历史会话查看
- SessionDB 新增 `get_session()` 和 `get_session_by_index()` 方法
- CLI 新增 `/history show <目标名|#序号>` 查看完整对话记录

---

## 阶段五：准确性与速度提升

### 风险评分 v2
- 加权矩阵替代简单公式：威胁标签 × 基础设施可信度 × 域名年龄 × ICP 备案 × 行为模式
- 新增域名年龄加权（<7天 x2, >5年 x0.6）
- 新增标签置信度降权（低置信度标签自动降权）
- 新增恶意 ASN 加分（psychz/dacentec x1.3）

### 快速拦截
- CTIA 高置信度恶意直接输出，跳过后续工具调用
- CTIA white + 老域名 + ICP + 高流行度也直接判定安全

### 并行调用引导
- prompt 明确要求 LLM 每轮尽可能一次性调用多个独立工具
- 按深度限制迭代次数：quick 5 轮，standard 10 轮，deep 15 轮

### 结构化证据链
- LLM 输出格式升级为 `{source, data, conclusion}` 结构化 findings
- 新增 `evidence_chain` 步骤追踪

---

## 阶段六：输入类型扩展

### 样本哈希分析
- `detect_target_type()` 识别 MD5/SHA1/SHA256
- 新增 `sample-hash-analysis` 技能
- 路由到 `qianxin_fdp_sample__sandbox` + CTIA 工具

### CVE 漏洞分析
- `detect_target_type()` 识别 CVE-YYYY-NNNN 格式
- 新增 `cve-vulnerability-analysis` 技能
- 路由到 `ctia_exploit__v1_exploit` 工具

### 追问约束
- 上下文注入：每次追问自动注入当前分析目标
- prompt 规则：只回答与当前目标安全相关的问题

---

## 阶段七：部署与分发

### git + pipx 方案
- 项目推送到 GitHub: https://github.com/redbad2/secagent.git
- 用户安装：`pipx install git+https://github.com/redbad2/secagent.git`

### 配置导出
- `secagent config export` 导出完整配置（含 API key，自动解析环境变量引用）
- 新机器复制 config.export.yaml → ~/.secagent/config.yaml

### 版本管理
- 版本号从 `__init__.py` 动态读取
- banner 自动显示当前版本
- `secagent update` 自动检测安装方式（pipx/pip/git）并升级

---

## 阶段八：评审反馈修复（v0.2.0）

### P0 修复
- conftest.py `builtin_skills_dir` 路径修正为 `secagent/skills`（包内）
- agent.py 新增 12 个单元测试（mock LLM+MCP，覆盖 _run_loop 核心路径）

### P1 增强
- IPv6 支持：`is_valid_ip` 改用 `ipaddress.ip_address()` 校验
- MCP 重试机制：`_call_tool_with_retry` 失败自动重试 2 次，指数退避
- 流式输出：`_run_loop` 全量使用 `stream=True`，`on_stream` 回调逐块输出
- 批量并行化：`_run_batch` 改用 `asyncio.gather` + `Semaphore(3)` 并发分析

---

## 技能整合（从 third_skills 提取）

从 12 个第三方技能文件中提取有价值内容：

### 整合到已有技能
- domain-security-analysis：从 7 步通用流程升级为 16 节点 SOP（222 行）
- ip-security-analysis：加入组件漏洞查询步骤和验证清单（117 行）

### 新建技能
- bulk-registration-detection（57 行）：批量注册域名检测方法论
- unknown-threat-detection（63 行）：低流量域名未知威胁发现方法
- tool-output-reference（123 行）：Hunter/CTIA/FDP/Libra 工具输出字段参考
- sample-hash-analysis（63 行）：样本哈希分析 SOP
- cve-vulnerability-analysis（63 行）：CVE 漏洞分析 SOP

### 跳过的内容
- Libra 专用工具技能（filter-condition-query、get-history-skeleton 等）
- Zion 文件分析平台（与域名/IP 分析无关）
- 通用搜索技能（与 Exa/web_fetch 重叠）

---

## 最终状态（v0.2.0）

| 指标 | 数值 |
|------|------|
| 核心源码 | ~3000 行 |
| 测试 | 89 个（9 个测试文件） |
| 技能 | 8 个 |
| 依赖 | 6 个（openai, mcp, rich, prompt_toolkit, pyyaml, httpx） |
| 支持输入 | 域名、IPv4/IPv6、MD5/SHA1/SHA256、CVE |
| MCP 工具 | 16 个 server，39+ 个工具 |

## 关键教训

1. MCP 的 anyio task group 要求同一 task 中 enter/exit，不能跨 task
2. logging filter 比 setLevel 更彻底，库可能自己加 handler 绕过 setLevel
3. `stream=True` 返回的是迭代器，需要手动拼装 tool_calls delta
4. 环境变量引用（${VAR}）在导出时需要展开，否则新机器读不到
5. Python 3.12+ 的 PEP 668 禁止直接 pip install，必须用 venv 或 pipx
