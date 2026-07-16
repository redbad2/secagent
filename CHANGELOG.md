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

---

## 阶段九：产品化打磨（v0.2.4 ~ v0.2.8）

### v0.2.4: JSON 提取增加 LLM 结构化 fallback
- LLM 输出的 JSON 正则匹配失败时，用 `response_format={"type":"json_object"}` 让 LLM 再次提取

### v0.2.5: /exit 不再触发事后学习提示
- 用户主动退出时不弹出技能创建确认

### v0.2.6: 截掉 JSON 后的 LLM 自言自语
- `_strip_post_json_noise()` 截掉 LLM 在 JSON 块后的内心独白，只渲染纯分析报告

### v0.2.7: 新增 /models show|switch 命令
- 交互模式下查看和临时切换模型

### v0.2.8: 修复会话中 /analyze 跨 task anyio 冲突
- REPL 中 /analyze 先结束当前会话再执行新分析，避免 anyio cancel scope 冲突

---

## 阶段十：安全加固（v0.2.9 ~ v0.3.2）

### v0.2.9: 安全加固
- 新增 `secure_write()`：O_CREAT|O_WRONLY|O_TRUNC，权限 0o600
- 新增 `secure_mkdir()`：目录权限 0o700
- config export 路径限制（禁止绝对路径和 .. 穿越）
- web_fetch SSRF 防护：`_is_safe_url()` 检查内网/保留地址
- SessionDB + MonitorDB 加 WAL 模式和 `threading.Lock`（SQL 注释称已加锁，实际未使用）
- 凭证文件（MEMORY.md、skills、config.export）全部改用 secure_write

### v0.3.0: P0 功能修复
- `/compare` 命令加入 REPL dispatch 和 Tab 补全
- 批量 `--output` CSV 导出实际生效
- `/save` 提示修正
- `/models`、`/end`、`/new` 加入补全器

### v0.3.1: 安全复核修复
- `/compare` dispatch 加 `from secagent.compare import cmd_compare`（修复 NameError 回归）
- SQLite 锁假修复：`SessionDB`/`MonitorDB` 所有方法接入 `with self._lock`
- config export 路径检查从 `startswith` 改为 `relative_to`（修复兄弟目录绕过）
- `secure_write` 异常路径修复（仅在 fdopen 失败时 close，避免 double-close）
- SSRF 补全地址类型（组播/未指定/CGN 100.64/10）
- 重定向绕过修复（`follow_redirects=False`，手动跟随并每跳复检）
- analyze/batch `--output` 改用 secure_write

### v0.3.2: 剩余安全加固
- `save_skill` 内容防护：Skill.source 区分 builtin/user，content 上限 8192 字符，超长截断
- 日志凭证脱敏：`redact_secrets()` 覆盖 URL userinfo + 敏感 header
- `cmd_update` 升级前展示信任源并要求确认
- 会话中 `/batch`、`/monitor`、`/compare` 统一先结束会话（避免 anyio 冲突）

---

## 阶段十一：depth 实质化（v0.3.3 ~ v0.3.6）

### v0.3.3: depth 实质化 + compare 增强
- `max_iterations` 随 depth 变化（quick 5 / standard 10 / deep 15）
- deep 额外连接 OPTIONAL_SERVERS + 加载 `threat-intel-correlation` 技能
- prompt deep 注入 5 步实质 SOP（关联资产追溯/多源交叉验证/历史对比/父子域名追溯/行为模式分析）
- compare 显示新增工具集合差异对比

### v0.3.4: 复杂域名超时崩溃修复
- `_loop_runner.run` 超时按 depth 区分（quick 180s / standard 600s / deep 900s）
- `asyncio.gather` 正确处理 `CancelledError`（`BaseException` 非 `Exception` 子类）
- sync 模式补 `asyncio.wait_for` 超时保护

### v0.3.5: save_skill 缺参崩溃修复
- `_save_skill_wrapper` 的 `trigger` 参数加默认值
- `_run_loop` 内置工具调用加 `_safe_builtin` 闭包 protect

### v0.3.6: /version 命令
- 交互式 `/version` + 命令行 `secagent --version`

---

## 阶段十二：分析准确性提升（v0.4.0 ~ v0.4.1）

### v0.4.0: 风险评分交叉验证
- 新增 `extract_signals()`：从 MCP 工具返回文本中正则提取 threat_labels/domain_age_days/has_icp/infra_org/confidence
- `compute_risk_score` 死代码被激活，与 LLM 自报等级双轨展示
- AnalysisResult 新增 independent_risk_level/score/confidence/risk_discrepancy 字段
- 独立置信度 = 数据源数量 + 信号提取完整度
- 有分歧时黄色标注

### v0.4.1: 序列化 + monitor 并发 + MCP 健康检查 + token 统计
- AnalysisResult 新增 `from_dict()` 反序列化，`to_dict()` 补全 raw_output
- monitor run 从串行改为 `Semaphore(3)+gather` 并发，加 `--concurrency` 参数
- `MCPManager.health_check()` + `/status` 命令 + `secagent status` 子命令
- token 用量统计：`stream_options={include_usage}` + chunk.usage 捕获，展示在报告末尾

---

## 阶段十三：服务化与集成（v0.5.0 ~ v0.5.1）

### v0.5.0: API 服务化
- 新建 `secagent/server.py`，FastAPI 提供 7 个端点
- `secagent serve [--host] [--port]` 启动，自动生成 /docs
- 依赖：fastapi>=0.100, uvicorn>=0.20

### v0.5.1: Webhook 告警
- 新建 `secagent/notify.py`，HTTP POST JSON，超时 10s
- config.yaml 新增 `notify` 段：`webhooks[].url` + `min_risk` 阈值
- monitor run 检测到变化时自动推送告警

---

## 阶段十四：误报抑制与体验增强（v0.6.0）

### v0.6.0: 误报抑制 + 技能管理 + 配置热重载
- CDN/WAF 误报抑制：`extract_signals` 新增 `is_cdn_ip` 检测，产生误报警告
- 技能管理增强：Skill.enabled + `.disabled` 标记文件 + enable/disable 方法
- `/skills enable/disable <name>` + `/skills test <target>`（预览技能匹配）
- `/config reload` 热重载配置文件
- `/models switch` 改为持久化到 config.yaml

---

## 最终状态（v0.6.0）

| 指标 | 数值 |
|------|------|
| 核心源码 | ~5000 行 |
| 测试 | 101 个 |
| 技能 | 8 个 |
| 依赖 | 8 个（openai, mcp, rich, prompt_toolkit, pyyaml, httpx, fastapi, uvicorn） |
| 支持输入 | 域名、IPv4/IPv6、MD5/SHA1/SHA256、CVE |
| MCP 工具 | 16 个 server，39+ 个工具 |
| 新增模块 | server.py（API）、notify.py（告警）、result_parser 独立评分引擎 |

---

## 阶段十五：内部可用度增强（v0.7.0）

### v0.7.0: 连接并行化 + 配置校验 + 结果缓存 + 上下文裁剪

**内部可用度提升**（降低首屏延迟、启动即报错、避免重复烧 token）：

- **MCP 连接并行化**（mcp_manager.py）：改 worker task 模式，每个连接由一个常驻 task 持有完整生命周期（enter→保持→exit），多 worker 并行握手降首屏延迟。关键约束：streamablehttp_client 内部 anyio.create_task_group 要求 `__aenter__`/`__aexit__` 同 task，直接 gather 会跨 task 报错，必须 worker task。`_discover_tools` 也改 gather 并行。
- **启动期配置校验**（config.py）：新增 `validate_config() -> (errors, warnings)`，LLM api_key/base_url/model 缺失为 error，MCP server 缺凭证（fdp-access/x-authtoken/authorization 等）为 warning。CLI 启动时校验，LLM 依赖命令在 error 时退出，管理命令仍可运行排查。
- **结果复用缓存**（新增 cache.py）：`ResultCache`（SQLite WAL + Lock，键 target+depth，默认 TTL 1h）。`analyze --reuse` 命中缓存跳过 LLM 与 MCP 调用；`AnalysisResult` 加 `from_cache` 字段。

**上下文膨胀控制**（ecdd8b0，工具返回裁剪 + 历史滑窗）：

- **Layer A 裁剪**（prune_tool_output）：`_extract_content` 按阈值裁剪工具返回，信号保留区 + 结构感知（JSON 数组留前5条/JSON 对象删低价值字段/纯文本头尾保留）。
- **Layer B 滑窗**（_maybe_slide_window）：tool 消息超阈值时降级早期消息为信号摘要，保留最近几轮完整。
- **重构 extract_signals**：抽出 `extract_signals_from_text` 纯函数，`extract_signals` 改逐条提取+合并（domain_age 取最小/icp·cdn 任一真/org·conf 取首个）。

**P1 修复（降级信号提取）**：
- 滑窗降级保留区格式 `tag=c2 | conf=0.90` 与 extract_signals_from_text 的 JSON 正则不匹配，导致降级后 compute_risk_score 丢失早期信号。
- 修复：extract_signals_from_text 增加保留区 `key=value` 格式补充解析（仅在文本含 `[已降级`/`[关键信号` 标记且 JSON 正则未提取到时生效，避免误匹配）。
- 补测试：降级格式解析、prune 保留区兜底、普通文本不误匹配、降级后端到端 extract_signals 仍可提取。

**P2 修复**：6 个文件末尾补回换行符（agent.py 等原本有，属回归）。

---

## 最终状态（v0.7.0）

| 指标 | 数值 |
|------|------|
| 核心源码 | ~5500 行 |
| 测试 | 149 个（+cache 8/validate 7/reuse 1/context_pruning 26+4） |
| 技能 | 8 个 |
| 依赖 | 8 个 |
| 新增模块 | cache.py（结果缓存） |
| 新增能力 | MCP 并行连接、配置校验、结果复用、上下文裁剪+滑窗 |

---

## 阶段十六：自身安全与循环健壮性（v0.8.0）

### v0.8.0: save_skill 注入防护 + AsyncOpenAI + 迭代上限 salvage

**P0-1 save_skill 提示注入通道审核**：

- 背景：LLM 可经 save_skill 工具把内容写入技能并即时生效，而 user 技能会注入后续所有分析的 system prompt —— 恶意页面可经 web_fetch 上下文诱导 LLM 写入攻击者控制的技能，形成持久化注入。
- `learning.py`：`create_skill()` 新增 `quarantine` 参数（创建即写 `.disabled` 标记，不参与后续匹配）；新增 `audit_skill_content()` 静态审计（中英文角色覆盖指令、伪造 `system:` 指令、诱导调用工具、外链 URL、疑似 base64 载荷）。
- `agent.py`：LLM 经 save_skill 创建的技能默认隔离待审核；审计命中时即使配置 `on` 也强制隔离。
- `cli.py`：`/skills enable` 增加内容预览 + 审计警告 + y/n 确认（原为无确认直接启用）；`/save` 手工保存后跑审计提示。
- `config.py`：新增 `skills.llm_create`（off=禁止 | quarantine=禁用待审核（默认） | on=直接启用）。

**P0-2 AsyncOpenAI 解除事件循环阻塞**：

- 问题：`_run_loop` 用同步 OpenAI client 做流式调用，整个流式期间阻塞 event loop，`serve` 模式 `/batch`、`/monitor/run` 的 `Semaphore(3)` 并发实际退化为串行。
- 修复：改用 `AsyncOpenAI` + `async for`；流式读取抽为 `_stream_completion()` 辅助方法。
- 同步辅助调用（结果解析 fallback、事后学习技能提炼）在 analyze/end_session 的 4 个调用点改 `asyncio.to_thread`，事件循环内零阻塞 LLM 调用。

**P0-3 迭代上限 salvage**：

- 问题：达到 max_iterations 后直接拿最后一条 assistant 内容或输出"分析未完成"，已完成的工具调用结果全部浪费。
- 修复：新增 `_salvage_final_output()` —— 已收集工具数据时追加"禁止工具调用"指令再发起一次补全（不计入迭代数），强制基于已有信息按既定 JSON 格式输出最终结论；salvage 失败时回退原有兜底。

**测试**：mock 从同步 client 迁移到 `llm_async`（`_async_stream`/`_mock_llm` 辅助），新增 salvage 成功/失败兜底、save_skill 隔离/off/审计强制隔离/干净放行、隔离创建、7 类审计模式共 17 个用例。

---

## 最终状态（v0.8.0）

| 指标 | 数值 |
|------|------|
| 核心源码 | ~5800 行 |
| 测试 | 171 个 |
| 技能 | 8 个 |
| 依赖 | 8 个 |
| 新增能力 | save_skill 隔离审核 + 内容审计、AsyncOpenAI 真并发、迭代上限 salvage |
