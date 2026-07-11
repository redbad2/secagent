# secagent

CLI 安全分析 Agent — 输入域名、IP、样本哈希或 CVE 编号，自主调用 MCP 工具链判断安全风险。

## 快速开始

```bash
# 安装
pipx install git+https://github.com/redbad2/secagent.git

# 配置 API key
vim ~/.secagent/config.yaml

# 分析
secagent analyze baidu.com
secagent analyze 8.8.8.8 --format json
secagent analyze d41d8cd98f00b204e9800998ecf8427e  # 样本哈希
secagent analyze CVE-2024-1234                       # CVE 漏洞

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

- **自主分析循环** — OpenAI SDK tool calling + MCP 工具并行调用
- **多轮追问** — 分析完成后可继续追问，保持 MCP 连接和对话历史
- **快速拦截** — 高置信度恶意直接输出，避免过度查询
- **自我学习** — 复杂分析自动创建技能，误报模式自动记录
- **多模型路由** — 按分析深度选择模型
- **内置 web_fetch** — 直接访问目标页面查看实际内容
- **Exa 搜索** — 搜索公开安全情报
- **定时监控** — 添加监控目标，定期扫描检测变化
- **策略对比** — A/B 对比不同分析深度的结果
- **思考过程展示** — 显示 LLM 的中间推理过程

## 子命令

```
secagent analyze <target>        # 分析域名/IP/哈希/CVE
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
secagent config export           # 导出配置（用于部署到新机器）
secagent update                  # 升级 secagent
```

## 交互式命令

```
/analyze <target>  — 分析域名/IP/哈希/CVE
/batch <file>      — 批量分析
/skills list       — 技能管理
/memory show       — 记忆管理
/history list      — 历史管理
/history show <t>  — 查看完整会话
/config show       — 配置管理
/config export     — 导出配置
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

models:
  fast: deepseek-chat
  standard: deepseek-chat
  reasoning: deepseek-reasoner

agent:
  max_iterations: 20

web_fetch:
  enabled: true
  verify_ssl: false

exa:
  enabled: true

mcp_servers:
  qianxin_fdp_domain:
    url: https://fdp.qianxin.com/mcp/v1/domain/
    headers:
      fdp-access: "your-key"
      fdp-secret: "your-secret"
  # ... 其他 server
```

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
│   ├── result_parser.py  # 结果解析 + 风险评分
│   ├── web_fetch.py      # 内置页面抓取
│   ├── monitor.py        # 定时监控
│   ├── compare.py        # 策略对比
│   └── skills/           # 预置技能（8个）
├── tests/                # 测试套件（77个测试）
├── config.template.yaml  # 配置模板
├── install.sh            # 安装脚本
├── pyproject.toml
└── README.md
```

## 依赖

- Python 3.11+
- openai, mcp, rich, prompt_toolkit, pyyaml, httpx
