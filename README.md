# secagent

CLI 安全分析 Agent — 输入域名或 IP，自主调用 MCP 工具链判断安全风险。

## 快速开始

```bash
# 安装
cd secagent
bash install.sh

# 单次分析
secagent analyze baidu.com
secagent analyze 8.8.8.8 --format json
secagent analyze evil.com --format markdown -o report.md

# 交互式模式（支持分析后追问）
secagent
secagent> baidu.com
secagent(baidu.com)> 这个域名的子域名有哪些风险？
secagent(baidu.com)> /end
secagent>
```

## 功能特性

- **自主分析循环** — OpenAI SDK tool calling + MCP 工具并行调用，自动决定调用哪些工具
- **多轮追问** — 分析完成后可继续追问，保持 MCP 连接和对话历史
- **自我学习** — 复杂分析自动创建技能，误报模式自动记录到记忆
- **多模型路由** — 按分析深度选择模型（quick → chat，deep → reasoner）
- **内置 web_fetch** — 直接访问目标页面查看实际内容
- **Exa 搜索** — 搜索公开安全情报，与内部情报交叉验证
- **定时监控** — 添加监控目标，定期扫描检测变化
- **策略对比** — A/B 对比不同分析深度的结果差异

## 子命令

```
secagent analyze <target>        # 分析域名/IP
secagent batch <file>            # 批量分析
secagent monitor list            # 查看监控目标
secagent monitor add <target>    # 添加监控
secagent monitor run             # 执行监控扫描
secagent compare <target>        # 策略对比
secagent skills list             # 查看技能
secagent memory show             # 查看记忆
secagent history list            # 查看历史
secagent history show <target>   # 查看完整会话
secagent config show             # 查看配置
```

## 交互式命令

```
/analyze <target>  — 分析域名或IP
/batch <file>      — 批量分析
/skills list       — 技能管理
/memory show       — 记忆管理
/history list      — 历史管理
/history show <t>  — 查看完整会话
/config show       — 配置管理
/monitor list      — 监控管理
/compare <target>  — 策略对比
/end               — 结束当前会话
/new               — 开始新分析
/help              — 帮助
/exit              — 退出
```

## 配置

配置文件：`~/.secagent/config.yaml`

```yaml
llm:
  base_url: https://api.deepseek.com/v1
  api_key: sk-xxx
  model: deepseek-chat
  temperature: 0.1

models:                    # 多模型路由
  quick: deepseek-chat
  standard: deepseek-chat
  deep: deepseek-reasoner

agent:
  max_iterations: 20       # LLM 最大迭代次数
  timeout: 300             # 超时秒数

web_fetch:
  enabled: true            # 内置页面抓取
  verify_ssl: false        # 是否验证 SSL 证书

exa:
  enabled: true            # Exa 搜索

mcp_servers:               # MCP 服务器配置
  server_name:
    url: https://...
    headers:
      Authorization: Bearer xxx
```

## MCP 工具链

secagent 连接以下 MCP server 获取安全分析能力：

| Server | 能力 |
|--------|------|
| ctia_domain / ctia_ip | 威胁情报（标签、风险等级、恶意家族） |
| qianxin_fdp_domain / qianxin_fdp_ip | 基础数据（PDNS、WHOIS、TLS、ICP、流行度） |
| hunter_mcp | 网络空间测绘（开放端口、服务组件、漏洞） |
| iporg | IP 归属组织查询 |
| secagent | 综合分析（12 检测器 + 2 LLM） |
| exa | 公开情报搜索 |

## 自我学习

- **技能自动创建** — 复杂分析（工具调用 ≥8 次）后，提示用户是否将分析方法保存为技能
- **记忆自动更新** — 误报模式、IOC 摘要自动写入 MEMORY.md，注入后续分析的系统提示
- **会话存档** — 每次分析的完整对话历史保存到 SQLite，支持全文检索

## 技能系统

预置 6 个安全分析技能，自动匹配目标类型加载：

| 技能 | 触发条件 | 内容 |
|------|----------|------|
| domain-security-analysis | 域名 | 16 节点 SOP |
| ip-security-analysis | IP | 7 步工作流 |
| threat-intel-correlation | 深度分析 | 多源交叉验证 |
| bulk-registration-detection | 批量注册 | 批量域名检测方法 |
| unknown-threat-detection | 未知威胁 | 低流量域名筛选 |
| tool-output-reference | 参考 | 工具输出字段文档 |

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
│   ├── result_parser.py  # 结果解析 + 风险评分
│   ├── web_fetch.py      # 内置页面抓取
│   ├── monitor.py        # 定时监控
│   └── compare.py        # 策略对比
├── skills/               # 预置技能
├── tests/                # 测试套件
├── pyproject.toml
├── install.sh
└── README.md
```

## 依赖

- Python 3.11+
- openai, mcp, rich, prompt_toolkit, pyyaml, httpx

## 测试

```bash
python -m pytest tests/ -v
```
