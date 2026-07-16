# secagent

CLI 安全分析 Agent — 输入域名、IP、样本哈希或 CVE 编号，自主调用 MCP 工具链判断安全风险。

## 快速开始

```bash
# 安装
pipx install git+https://github.com/redbad2/secagent.git

# 配置 API key（首次使用需填入 DeepSeek + MCP 服务凭证）
cp config.template.yaml ~/.secagent/config.yaml
vim ~/.secagent/config.yaml

# 分析（--depth 控制分析深度，详见下文"分析深度与策略选择"）
secagent analyze baidu.com                          # 默认 standard 深度
secagent analyze 8.8.8.8 --depth quick --format json   # 快速初筛
secagent analyze d41d8cd98f00b204e9800998ecf8427e     # 样本哈希
secagent analyze CVE-2024-1234 --depth deep            # 深度研判

# 交互式模式（支持分析后追问）
secagent
secagent> baidu.com
secagent(baidu.com)> 这个域名的子域名有哪些风险？
secagent(baidu.com)> /end
```

## 支持的输入类型

| 类型 | 示例 | 自动路由的工具 |
|------|------|---------------|
| 域名 | `baidu.com` | CTIA + FDP + Hunter + Exa |
| IP | `1.2.3.4` | CTIA + FDP + Hunter + iporg |
| 样本哈希 | `d41d8cd98f00b204...` (MD5/SHA1/SHA256) | FDP Sample + CTIA |
| CVE 漏洞 | `CVE-2024-1234` | CTIA Exploit |

## 功能特性

- **自主分析循环** - OpenAI SDK tool calling + MCP 工具并行调用
- **独立风险评分** - compute_risk_score 加权矩阵交叉验证 LLM 判断
- **多轮追问** - 分析完成后可继续追问，保持 MCP 连接和对话历史
- **快速拦截** - 高置信度恶意直接输出，避免过度查询
- **误报抑制** - 自动检测 CDN/WAF 共享 IP，标注潜在误报
- **自我学习** - 复杂分析自动创建技能，误报模式自动记录
- **多模型路由** - 按分析深度选择模型
- **内置 web_fetch** - 直接访问目标页面查看实际内容
- **Exa 搜索** - 搜索公开安全情报
- **定时监控** - 添加监控目标，定期扫描检测变化，变化时 webhook 告警
- **策略对比** - A/B 对比不同分析深度的结果
- **HTTP API** - FastAPI 服务化，可被 SOAR/SIEM 平台集成
- **思考过程展示** - 显示 LLM 的中间推理过程
- **token 用量统计** - 每次分析展示 prompt/completion 消耗

## 分析深度与策略选择

分析深度（`--depth`）不只是换模型，它会**实质影响分析的深度和广度**：

| 维度 | `quick` | `standard` | `deep` |
|------|---------|------------|--------|
| 工具调用轮数上限 | 5 | 10 | 15 |
| 使用模型 | `models.fast` | `models.standard` | `models.reasoning` |
| 连接的 MCP server | 仅核心 | 仅核心 | 核心 + 辅助（grep/exa/brave 等已配置的） |
| 加载的技能 | 基础 | 基础 | 基础 + 多源交叉验证技能（`threat-intel-correlation`） |
| prompt 指令 | 仅查询威胁情报 | 完整技能流程 | 关联资产追溯 + 多源交叉验证 + 历史对比 + 父子域名追溯 + 行为模式分析 |
| 适用场景 | 快速初筛、批量监控 | 日常分析 | 高风险目标深度研判、需要交叉验证时 |
| 预估耗时 | ~30s-1min | ~1-2min | ~2-5min |

### 三种使用场景下的指定方式

**子命令模式**（直接指定 `--depth`）：
```bash
secagent analyze example.com --depth quick      # 快速初筛
secagent analyze 1.2.3.4 --depth standard       # 日常分析（默认）
secagent analyze example.com --depth deep      # 深度研判
```

**交互式 REPL**（REPL 中 `/analyze` 和直接输入默认用 standard，如需 deep 请用子命令模式）：
```
secagent
secagent> baidu.com                  # 默认 standard 深度
secagent> /analyze baidu.com          # 默认 standard 深度
```

> 注意：交互式模式暂不支持在 REPL 内切深度。需要 deep 分析时，请退出 REPL
> 用 `secagent analyze <target> --depth deep` 子命令执行，或在子命令模式
> 分析后进入 REPL 追问（`secagent` → `/analyze`）。

**策略对比**（对比不同深度的分析差异）：
```bash
secagent compare example.com --depths quick,standard,deep
secagent compare example.com --depths quick,deep
```
> 对比结果会展示：风险等级一致性、工具调用集合差异（哪些工具只在 deep 调用）、
> 发现数/IOC 数差异，帮助你判断深度提升是否带来实质信息增益。

### 模型路由配置

深度对应的模型在配置文件 `~/.secagent/config.yaml` 的 `models` 段定义：

```yaml
models:
  fast: "deepseek-chat"          # quick 深度使用
  standard: "deepseek-chat"      # standard 深度使用
  reasoning: "deepseek-reasoner" # deep 深度使用（建议用推理模型）
```

> 如果不配置 `models` 段，三种深度都回退到 `llm.model`。
> 运行时可用 `/models show` 查看当前路由，`/models switch <model>` 临时切换默认模型（仅当前会话生效）。

## 子命令

```
secagent analyze <target> [--depth quick|standard|deep] [--format text|json|markdown] [-o 文件]
                                   # 分析域名/IP/哈希/CVE
secagent batch <file> [--output 文件.csv]  # 批量分析（quick 深度，并发，可导出 CSV）
secagent monitor list                     # 查看监控目标
secagent monitor add <target>             # 添加监控
secagent monitor remove <target>          # 移除监控
secagent monitor run [--depth quick|standard]  # 执行监控扫描
secagent monitor history <target>        # 查看监控历史
secagent compare <target> [--depths quick,standard,deep]  # 策略对比
secagent skills list                      # 查看技能
secagent memory show                      # 查看记忆
secagent history list                     # 查看历史
secagent history show <target>            # 查看完整会话
secagent config show                      # 查看配置
secagent config export                    # 导出配置（含 API key，0o600 权限）
secagent config reload                    # 热重载配置文件
secagent status                           # MCP 服务器健康检查
secagent serve [--host HOST] [--port PORT] # 启动 HTTP API 服务
secagent --version                        # 显示版本
secagent update                           # 升级 secagent
```

## 交互式命令

```
/analyze <target>    - 分析域名/IP/哈希/CVE（默认 standard 深度）
/batch <file>        - 批量分析
/compare <target>    - 策略对比
/models show         - 查看模型路由配置
/models switch <m>   - 切换并持久化默认模型
/skills list         - 列出所有技能（含启用状态和来源）
/skills show <name>  - 查看技能详情
/skills enable <name>  - 启用技能
/skills disable <name> - 禁用技能
/skills delete <name>  - 删除技能
/skills test <target>  - 预览某目标会匹配到哪些技能
/memory show         - 记忆管理
/history list        - 历史管理
/history show <t>    - 查看完整会话
/config show         - 配置管理
/config export       - 导出配置（0o600 权限）
/config model <m>    - 切换模型（仅内存）
/config reload       - 热重载配置文件
/monitor list        - 监控管理
/monitor add <t>     - 添加监控目标
/monitor remove <t>  - 移除监控
/monitor run         - 执行监控扫描
/save <名>:<触发>    - 保存分析经验为技能
/status              - MCP 服务器健康检查
/end                 - 结束当前会话（触发事后学习）
/new                 - 结束当前会话，开始新分析
/help                - 帮助
/version             - 显示版本信息
/exit                - 退出（不触发事后学习）
```

## 配置

配置文件：`~/.secagent/config.yaml`（目录权限 0o700，导出文件 0o600）

```yaml
# === LLM 配置（必填）===
llm:
  base_url: https://api.deepseek.com/v1
  api_key: sk-xxx
  model: deepseek-chat           # 默认模型，也作为 models 未配置时的回退
  temperature: 0.1

# === 多模型路由（按分析深度选模型，详见上文"分析深度与策略选择"）===
models:
  fast: deepseek-chat            # quick 深度
  standard: deepseek-chat        # standard 深度
  reasoning: deepseek-reasoner   # deep 深度（建议用推理模型）

# === Agent 参数 ===
agent:
  max_iterations: 20             # 各深度的统一上限（depth 自身取 5/10/15 再与之取 min）
  timeout: 300

# === 内置工具 ===
web_fetch:
  enabled: true                   # web_fetch 工具开关
  verify_ssl: false              # 是否校验 SSL（安全分析常需看自签证书站点）

exa:
  enabled: true                  # Exa 搜索工具开关

# === 技能安全 ===
skills:
  llm_create: quarantine         # LLM 自动创建技能策略：off=禁止 | quarantine=禁用待审核（默认） | on=直接启用

# === MCP 服务器 ===
mcp_servers:
  qianxin_fdp_domain:
    url: https://fdp.qianxin.com/mcp/v1/domain/
    headers:
      fdp-access: "your-key"
      fdp-secret: "your-secret"
  # ... 其他 server（详见 config.template.yaml）
```

> 配置优先级：环境变量 > `.env` 文件 > `config.yaml` > 默认值。
> 凭证可放在 `~/.secagent/.env`（`FDP_ACCESS_KEY=`、`CTIA_TOKEN=` 等）或直接写在 `config.yaml` 的 headers 里。
> 运行时改配置：`/config show` 查看、`/models switch <model>` 临时切换模型、`/config export` 导出完整配置到新机器。

## 定时监控

监控功能用于持续跟踪一批目标的安全状态变化。把关心的域名/IP 加入监控列表，
定期执行扫描，secagent 会自动对比每次的风险等级，有变化时高亮提醒。

```bash
# 1. 添加监控目标（自动识别 domain/ip 类型）
secagent monitor add mycompany.com
secagent monitor add 8.8.8.8

# 2. 查看监控清单
secagent monitor list

# 3. 执行一轮扫描（对所有启用目标重新分析，对比上次风险）
secagent monitor run                      # 默认 quick 深度（推荐，控制成本）
secagent monitor run --depth standard     # 更深分析

# 4. 查看某目标的历史变化轨迹
secagent monitor history mycompany.com

# 5. 移除监控
secagent monitor remove mycompany.com
```

> **没有硬编码的数量上限**，实际瓶颈在耗时和 token：监控是**串行**逐个分析的，
> 每目标 quick 深度约 30s-1min。建议监控目标控制在 20-50 个以内。
>
> Monitor 本身不带定时器，需配合系统调度周期执行：
> ```bash
> # crontab 示例：每天早 9 点扫描
> 0 9 * * * /path/to/secagent monitor run >> /var/log/secagent-monitor.log 2>&1
> ```

## HTTP API 服务

```bash
# 启动 API 服务
secagent serve                      # 默认 127.0.0.1:8000
secagent serve --host 0.0.0.0 --port 9000

# 访问自动生成的接口文档
open http://localhost:8000/docs
```

| 端点 | 方法 | 说明 |
|------|------|------|
| `/analyze` | POST | 分析单个目标，返回完整结果 JSON |
| `/batch` | POST | 批量分析（并发） |
| `/history` | GET | 查询历史会话 |
| `/monitor/list` | GET | 查看监控目标 |
| `/monitor/run` | POST | 触发监控扫描 |
| `/status` | GET | MCP 服务器健康状态 |
| `/version` | GET | 版本信息 |

## 告警通知

monitor run 检测到风险变化时，通过 webhook 自动推送告警。

```yaml
# config.yaml
notify:
  webhooks:
    - url: "https://hooks.example.com/alert"
  min_risk: "高"     # 可选：只在风险 >= 该等级时通知
```

通知格式：POST JSON `{event, timestamp, changes[], total_changes}`。

## MCP 工具链

| Server | 能力 |
|--------|------|
| ctia_domain / ctia_ip / ctia_exploit | 威胁情报、漏洞利用 |
| qianxin_fdp_domain / qianxin_fdp_ip / qianxin_fdp_sample | 基础数据、沙箱 |
| hunter_mcp | 网络空间测绘 |
| iporg | IP 归属查询 |
| exa | 公开情报搜索 |

## 自我学习

- **技能自动创建** — 复杂分析后提示用户保存为技能
- **技能创建审核** — LLM 通过 save_skill 创建的技能默认禁用待审核（内容含注入审计），
  `/skills show` 审查后 `/skills enable` 确认启用；可用 `skills.llm_create` 配置（off/quarantine/on）
- **记忆自动更新** — 误报模式自动写入 MEMORY.md
- **会话存档** — 完整对话历史保存到 SQLite

## 技能系统

预置 8 个安全分析技能：

| 技能 | 触发条件 |
|------|----------|
| domain-security-analysis | 域名 |
| ip-security-analysis | IP |
| threat-intel-correlation | 深度分析 |
| bulk-registration-detection | 批量注册 |
| unknown-threat-detection | 未知威胁 |
| tool-output-reference | 工具输出参考 |
| sample-hash-analysis | 样本哈希 |
| cve-vulnerability-analysis | CVE 漏洞 |

## 部署到新机器

```bash
# 在旧机器导出配置
secagent config export

# 复制到新机器
scp ~/.secagent/config.export.yaml newmachine:~/.secagent/config.yaml

# 在新机器安装
pipx install git+https://github.com/redbad2/secagent.git
```

## 升级

```bash
secagent update
```

## 测试

```bash
git clone https://github.com/redbad2/secagent.git
cd secagent
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## 项目结构

```
secagent/
├── secagent/
│   ├── agent.py          # 核心分析循环
│   ├── cli.py            # CLI + 交互式 REPL
│   ├── config.py         # 配置加载
│   ├── learning.py       # 自我学习层
│   ├── mcp_manager.py    # MCP 客户端管理
│   ├── prompt_builder.py # 系统提示构建
│   ├── result_parser.py  # 结果解析 + 独立风险评分
│   ├── web_fetch.py      # 内置页面抓取
│   ├── monitor.py        # 定时监控
│   ├── compare.py        # 策略对比
│   ├── server.py         # HTTP API 服务（FastAPI）
│   ├── notify.py         # Webhook 告警通知
│   └── skills/           # 预置技能（8个）
├── tests/                # 测试套件（101个测试）
├── config.template.yaml  # 配置模板
├── install.sh            # 安装脚本
├── pyproject.toml
└── README.md
```

## 依赖

- Python 3.10+
- openai, mcp, rich, prompt_toolkit, pyyaml, httpx, fastapi, uvicorn
