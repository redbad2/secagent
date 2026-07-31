# secagent 改进方案（基于 v0.9.2 代码评审）

> 基线版本：v0.9.2（commit 9c2969b），224 个测试全绿。
> 本文档替代 ROADMAP.md 成为当前执行的改进清单。每项包含：现状与问题 → 修改方案（含文件/行号）→ 验收标准。
> 评审中确认的上期 ROADMAP 完成状态见附录 A。
>
> **进度（截至 v0.10.0，commit c5309ac）**：P0×4、P1×3、P2×5 全部完成，251 个测试全绿；
> 剩余 P3-1（CI）、P3-2（serve 鉴权）、P3-3（数据集扩充）未做，另有 fixture/baseline 待真实配额生成（见 P1-1 备注）。

---

## 优先级总览

| 编号 | 改进点 | 类别 | 预估工作量 | 状态 |
|------|--------|------|-----------|------|
| P0-1 | `evaluate_result()` 引用不存在的 `critical` 属性（死代码 + AttributeError） | Bug | 0.5 天 | ✅ v0.10.0 |
| P0-2 | `server.py` connect 竞态 + 首请求类型过滤导致后续请求缺工具 | Bug | 0.5 天 | ✅ v0.10.0 |
| P0-3 | LLM 降级成功但未记录降级信号，报告误声明"未降级" | Bug | 0.2 天 | ✅ v0.10.0 |
| P0-4 | `install.sh` 技能复制路径失效（技能已移入包内） | Bug | 0.2 天 | ✅ v0.10.0 |
| P1-1 | 评估回放模式重设计：缓存工具返回而非最终结果 | 评估有效性 | 1.5 天 | ✅ v0.10.0（fixture 待生成） |
| P1-2 | 工具去重与路由（ROADMAP P1-3 顺延） | 成本/准确性 | 1~2 天 | ✅ v0.10.0 |
| P1-3 | 结构化最终输出 `response_format=json_object`（ROADMAP P2-5 顺延） | 健壮性 | 0.5 天 | ✅ v0.10.0 |
| P2-1 | 成本预算护栏（ROADMAP P2-4 顺延） | 成本 | 0.5 天 | ✅ v0.10.0 |
| P2-2 | 相似案例检索注入（ROADMAP P2-2 顺延） | 自我学习闭环 | 1 天 | ✅ v0.10.0 |
| P2-3 | `_extract_json` 重复代码合并到 generic.py | 可维护性 | 0.2 天 | ✅ v0.10.0 |
| P2-4 | 严重风险评估双路径合并（`evaluate_result` / `_evaluate_critical`） | 可维护性 | 0.5 天 | ✅ v0.10.0 |
| P2-5 | README 补 `secagent eval` 文档 | 文档 | 0.2 天 | ✅ v0.10.0 |
| P3-1 | GitHub Actions CI | 工程质量 | 0.5 天 | ❌ 未实现 |
| P3-2 | server.py API 鉴权 | 安全 | 0.5 天 | ❌ 未实现 |
| P3-3 | 评估数据集扩充（5 → 20+ 样本） | 评估有效性 | 持续 | ❌ 未实现（持续） |

依赖关系：P0 四项互不依赖可并行；P1-1 建议在 P1-2/P1-3 之前完成（后续改动靠它验证收益）；P2-4 依赖 P0-1。

---

## P0-1 `evaluate_result()` 引用不存在的 `critical` 属性

> ✅ 已完成（v0.10.0，1b913c8）：死代码块已删除，主路径简化为 assess → apply。

### 现状与问题

`secagent/agent.py:386-431` 的 `evaluate_result()`：

```python
if not learning_actions:
    if assessment.critical and not skill.critical:   # agent.py:426
        assessment.critical = True                    # no-op：条件已要求其为 True
        learning_actions.append("发现严重风险，标记为关键分析")
        if self.memory:
            self.memory.add(f"关键分析: {target} - {skill.risk_level}")
```

已验证的事实：

- `LearningAssessment`（`learning.py:452-460`）只有 5 个字段：`should_create_skill / skill_name / skill_trigger / memory_facts / reason`，**没有 `critical`**。
- `AnalysisResult`（`result_parser.py:22-38`）同样**没有 `critical`**。
- `LearningTrigger.assess()` 从不设置 `critical`。
- 因此当 `learning_actions` 为空时（如记忆去重后无新增），`assessment.critical` 必抛 `AttributeError`。
- 调用点 `analyze()`（agent.py:285-292）用 `except Exception` 兜底，错误被静默吞掉，仅 log warning——**"严重风险评估"这条路径实际上从未成功执行过**。
- `tests/` 中无任何 `evaluate_result` 的测试（已 grep 确认）。

### 修改方案

1. 决策：删除该死代码块（推荐），还是补全 `critical` 语义。
   - 推荐**删除**：`evaluate_result` 的核心价值是"高风险时强制评估学习"，这由 `assess()` + `apply()` 已完成；"关键分析"标记与现有 `memory_facts`（高/严重时已写入 `已知威胁` IOC）语义重复。
2. 具体改动（agent.py:425-431）：删除整个 `if not learning_actions:` 块，函数简化为仅保留 assess → apply → 评估打印的主路径。
3. 如决定保留语义，则在 `LearningAssessment` 增加 `critical: bool = False` 字段，`assess()` 中 `risk_level == "严重"` 时置 True，`apply()` 中据此写记忆。**二选一，不要保留现状。**

### 验收标准

- 新增单测：构造高风险 AnalysisResult + 记忆已含全部 facts（apply 返回空）→ `evaluate_result` 不抛异常。
- 全部测试保持绿。

---

## P0-2 `server.py` connect 竞态 + 首请求类型过滤导致后续请求缺工具

> ✅ 已完成（v0.10.0，1b913c8）：启动时一次性全量连接，请求路径不再判断连接状态。

### 现状与问题

`secagent/server.py:60-74`（`/analyze`）：

```python
if not agent._connected:
    await agent.connect(target_type=target_type, depth=req.depth)
```

两个问题：

1. **功能 bug**：`connect()` 按 `target_type` 过滤 server（domain 只连 `DOMAIN_SERVERS`）。若第一个请求是域名，`agent._connected=True` 后，**后续 IP 请求直接跳过 connect，IP 分析永远拿不到 iporg/ctia_ip 等 IP 专用工具**（反之亦然）。server 模式是长期驻留进程，必然遇到混合类型。
2. **竞态**：并发请求同时判断 `agent._connected == False`，会并发执行 `connect_all()`，重复建立 session（后建的覆盖先建的 `_sessions` dict 项，先建的 transport 泄漏）。
3. 次要：`agent._connected` 是私有属性的外部访问。

### 修改方案

1. `server.py::create_app()` 启动时（`@app.on_event("startup")` 或 `create_app` 内）**一次性 `await agent.connect()`（不传 target_type，连全部 server）**，请求处理路径不再判断连接状态。
2. 各端点删除 `if not agent._connected: await agent.connect(...)` 分支（`/analyze`、`/batch`、`/monitor/run` 共 3 处）。
3. `/monitor/run` 末尾的 `await agent.disconnect()`（server.py:156）改为不 disconnect（常驻服务不应每次扫描都断开）。
4. 私有属性访问改为 `agent.mcp.connected`（公开 property）。

### 验收标准

- 新增 `tests/test_server.py`（httpx ASGI transport + mock agent）：
  - 先 POST /analyze（domain）再 POST /analyze（IP）→ 两次都拿到完整工具集（断言 connect 只调用一次且 `server_names=None`）。
  - 并发 10 个 /analyze → connect 只调用一次。

---

## P0-3 LLM 降级成功但未记录降级信号

> ✅ 已完成（v0.10.0，1b913c8）：降级成功记录 degrade_reasons，后续迭代直接用 fallback 模型。

### 现状与问题

`agent.py::_run_loop` 中 LLM 调用失败降级（agent.py:587-604）：

```python
except Exception as e:
    fallback_model = self.config.models.fast or model
    response = self.llm.chat.completions.create(model=fallback_model, ...)
    logger.info("降级到模型 %s 成功", fallback_model)
    # ← 缺少 degraded = True 和 degrade_reasons.append(...)
```

对比 MCP 工具降级（agent.py:693-701）正确记录了 `degraded = True` + `degrade_reasons.append(...)`。

后果：LLM 从 reasoning 模型降级到 fast 模型后，`parse_analysis_result` 收到的 `degraded=False`、`degrade_reasons=[]`，报告尾部不标注降级，**用户不知道本次分析实际是用低配模型完成的**（v0.5.1 的双轨提示也依赖该信号）。另外当前实现下一轮迭代仍先用原 model，可能每轮都先失败一次再降级，浪费重试。

### 修改方案

`agent.py:595` 附近，降级重试成功后：

```python
degraded = True
degrade_reasons.append(f"LLM 降级到 {fallback_model}（原模型调用失败）")
model = fallback_model   # 后续迭代直接用 fallback
```

### 验收标准

- 单测：mock 主模型抛异常、fallback 成功 → `degrade_reasons` 含 LLM 降级记录；断言第二次 `create()` 调用的 model 参数为 fallback。

---

## P0-4 `install.sh` 技能复制路径失效

> ✅ 已完成（v0.10.0，1b913c8）：复制路径改为包内 `secagent/skills/`。

### 现状与问题

`install.sh:62-64`：

```bash
if [[ -d "$REPO_DIR/skills" ]]; then
    cp -r "$REPO_DIR/skills/"* "$SECAGENT_HOME/skills/" 2>/dev/null || true
```

技能已移入包内 `secagent/skills/`（`_find_builtin_skills()` 从包内加载，运行时不受影响），但 `$REPO_DIR/skills` 根目录已不存在 → 该步骤静默跳过，提示语误导。`install.sh:59` 的 `memory` 目录也从未被代码使用（MemoryStore 直接写 home 根下 `MEMORY.md`）。

### 修改方案

```bash
mkdir -p "$SECAGENT_HOME"/{skills,logs}
# 包内技能由 _find_builtin_skills() 自动加载，无需复制
```

删除 62-64 行的复制块（或改为打印"内置技能随包加载"说明）。

### 验收标准

- `bash install.sh` 输出无误导信息；安装后 `secagent skills list` 显示 8 个内置技能。


---

## P1-1 评估回放模式重设计：缓存工具返回而非最终结果

> ✅ 已完成（v0.10.0，0ef1047）：新增 `secagent/eval_replay.py`（extract_tool_outputs / ReplayableMCP /
> ScriptedLLM）；eval 回放改走 fixture（`tests/eval/fixtures/`），ResultCache 不再
> 用于 eval；`--save-fixtures` 在线生成 fixture；`SECAGENT_EVAL_FAKE_LLM=1` 离线冒烟；
> 死代码已清理；dataset.yaml 每样本含 fixture 字段。
>
> ⏳ 遗留（需真实 API 配额）：`tests/eval/fixtures/` 尚为空、`baseline.json` 未入库。
> 需执行 `secagent eval --online --save-fixtures` 生成快照并 `--save-baseline` 落盘，
> 之后回放与 `--check-baseline` 才实际生效（此前全部样本干净 SKIP，属设计行为）。

### 现状与问题

`eval.py::_eval_one` 回放模式调用 `agent.analyze(..., reuse=True)`，命中的是 `ResultCache` 中缓存的**最终 AnalysisResult**（`cache.py`，TTL 默认 1 小时）。两个根本缺陷：

1. **测不出代码变化**：改了 prompt、评分权重、解析逻辑后，回放仍返回缓存的旧结论——命中率永远不变，评估失去回归意义。ROADMAP P1-4 的原始设计是"用存档的**工具返回**代替真实 MCP 调用，重跑当前 LLM + 评分链"，实现与初衷不符。
2. **TTL 过期即不可复现**：缓存 1 小时后失效，`baseline.json` 无法长期作为回归基线；CI 上更不可能有缓存。

另外：`eval.py:194-198` 有一段 no-op 死代码（`if not online and (...): pass`），一并清理。

### 修改方案

1. **工具返回存档**：`SessionDB` 已存完整 `messages`（含所有 tool role 消息）。新增 `secagent/eval_replay.py`：
   - `extract_tool_outputs(session_messages) -> dict[key, content]`：从存档会话提取"工具调用 → 返回"的映射（key 建议 `(tool_name, json.dumps(args, sort_keys=True))`）。
   - 写入 `tests/eval/fixtures/<target>.json`（脱敏后入库）。
2. **回放执行**：新增 `ReplayableMCP`（实现与 `MCPManager.call_tool` 相同的接口），从 fixture 查表返回；查不到时返回固定 `"[replay miss]"` 文本。`agent.mcp = ReplayableMCP(...)` 后跑完整 `analyze()`——**LLM 调用、信号提取、双轨评分全部走当前代码**。
   - 回放仍需真实 LLM（评估本来就该花这笔钱）；可选 `SECAGENT_EVAL_FAKE_LLM=1` 走脚本化假 LLM 做纯逻辑冒烟。
3. `ResultCache` 不再用于 eval；`_eval_one` 删除 `reuse` 参数。
4. 删除 eval.py:194-198 死代码。
5. `dataset.yaml` 每条样本增加 `fixture: "<target>.json"` 字段。

### 验收标准

- `secagent eval`（回放模式）在无 MCP 网络、无 ResultCache 的环境下跑通，结果可复现。
- 单测：修改 `compute_risk_score` 权重后重跑回放 → 独立评分列随之变化（证明回放走当前代码）。
- `baseline.json` 入库并注明生成版本。

---

## P1-2 工具去重与路由（ROADMAP P1-3 顺延）

> ✅ 已完成（v0.10.0，0ef1047）：`config.py` 新增 `tool_routing`（能力组 → server 优先级，含默认值与
> template 示例）；`MCPManager.get_tool_definitions(server_filter, open_all_capabilities)`
> 同能力组默认只暴露最高优先级可用 server，首选失败回退组内下一个，deep 放开全组；
> `agent._call_cache` 调用级去重（canonical args 作 key，命中标注 (cached)，analyze 开始清空）。

### 现状与问题

39+ 个工具全量注入 prompt（`mcp_manager.py:269`），ctia_domain 与 fdp_domain 等能力重叠：工具描述占用大量 prompt token；LLM 可能用语义重复的工具重复查询同一目标。

### 修改方案

1. `config.py` 新增 `tool_routing: dict[str, list[str]]`（能力 → server 优先级），`AgentConfig` 加同名字段，`config.template.yaml` 给默认值：
   ```yaml
   tool_routing:
     domain_threat_intel: [ctia_domain, qianxin_fdp_domain]
     ip_threat_intel: [ctia_ip, qianxin_fdp_ip, iporg]
   ```
2. `MCPManager.get_tool_definitions(server_filter, capability_filter=None)`：同能力组默认只暴露最高优先级 server 的工具；`depth=deep` 或首选 server 在 `failed_servers` 中时放开全组。
3. `agent.py::_run_loop` 调用级去重：`self._call_cache: dict[tuple[str, str], str]`（key = `(tool_name, json.dumps(args, sort_keys=True))`），命中直接返回并在 tool 消息标注 `(cached)`；`analyze()` 开始时清空。
4. 与 P1-1 的 `ReplayableMCP` 保持 `call_tool` 签名一致。

### 验收标准

- 单测：路由过滤后工具数量符合预期；首选失败时 fallback 组内下一个；重复调用命中缓存不产生第二次 RPC（`mcp.call_tool` 调用次数断言）。
- 回放评估（P1-1 就位后）：命中率不回退，avg_tools 下降。


---

## P1-3 结构化最终输出（ROADMAP P2-5 顺延）

> ✅ 已完成（v0.10.0，c854f93 + 0ef1047 补全）：收敛轮追加"仅输出结论 JSON"指令；
> `structured_final` 仅 analyze 开启（追问保持自然语言）；补 3 个验收单测。

### 现状与问题

最终结论靠 `parse_analysis_result` 三级 fallback（```json 块 → 裸 JSON → LLM 再提取）从自然语言文本里抠 JSON，模型啰嗦或格式漂移时解析链路变长、失败率升高。`_salvage_final_output()`（agent.py:803-853）已验证 `response_format=json_object` 路径可行。

### 修改方案

1. `_run_loop` 收敛轮（本轮无 tool_calls 且 content 非空）重新发起一次补全：同 messages + `response_format={"type": "json_object"}`，prompt 要求只输出结论 JSON。注意：
   - 仅在 `iteration >= 2`（已有工具数据）时启用，避免浪费一次调用；
   - catch `400/BadRequest`（少数 OpenAI-compatible 端点不支持）后回落现有正则路径，并记录到 `degrade_reasons`。
2. `parse_analysis_result` 三级 fallback 保留为兼容层，不再是主路径。
3. token_usage 累加这次额外补全。

### 验收标准

- 单测：mock 支持 json_object → 主路径不依赖正则（断言未走 `_try_extract_bare_json`）；mock 400 → 回落正常且 degrade_reasons 有记录。

---

## P2-1 成本预算护栏（ROADMAP P2-4 顺延）

> ✅ 已完成（v0.10.0，9c9b72b）：`budget.max_tokens_per_analysis`；80% 注入收敛提示，100% 走 salvage，超限写 degrade_reasons。

### 修改方案

1. `config.py` 新增 `budget.max_tokens_per_analysis: int = 0`（0=不限），`AgentConfig` 同名字段。
2. `_run_loop` 每轮累加 `chunk.usage` 后检查：达 80% 时向 messages 注入 system 提示"token 预算即将耗尽，请基于已有数据立即给出结论"；达 100% 时 break 走 `_salvage_final_output()`。
3. 超限事件写入 `degrade_reasons`，报告尾部自然展示。

### 验收标准

- 单测：mock usage 序列超限 → 提前 salvage，degrade_reasons 含预算标注。

---

## P2-2 相似案例检索注入（ROADMAP P2-2 顺延）

> ✅ 已完成（v0.10.0，8125c4c）：目标+父域名 FTS5 top-3 注入 prompt；24h 内有历史时 CLI 提示 --reuse。

### 修改方案

1. `agent.py::analyze` 构建 system prompt 前：`SessionDB.search(target)` + 父域名各取 top-3（仅取 target/risk_level/summary/timestamp，不含 messages，单条截断 200 字符）。
2. `prompt_builder.py` 新增可选段"相似历史案例"，prompt 明确标注"历史结论仅供参考，必须重新用工具验证，禁止直接沿用"。
3. 与 `reuse` 的关系：`reuse=True` 已命中时跳过注入；24h 内同目标有历史且未用 reuse 时，CLI 提示可加 `--reuse`。

### 验收标准

- 单测：预置历史会话后 analyze → system prompt 含案例段；无历史 → 无注入；同目标 24h 内有历史 → CLI 有 reuse 提示。

---

## P2-3 `_extract_json` 重复代码合并

> ✅ 已完成（v0.10.0，9c9b72b）：`parsers/generic.py` 公开 `extract_json()`，ctia/fdp 复用。

### 现状与方案

`parsers/ctia.py:87-117` 与 `parsers/fdp.py:95-124` 的 `_extract_json` 逐字符括号匹配实现完全相同（约 30 行 ×2）。

- 移到 `parsers/generic.py` 为公开函数 `extract_json(text) -> str | None`，两处改为 import 复用。
- `result_parser.py::_try_extract_bare_json` 若逻辑等价也一并复用（核对后决定）。

### 验收标准

- 现有 `tests/test_parsers.py` 全绿，无行为变化。

---

## P2-4 严重风险评估双路径合并

> ✅ 已完成（v0.10.0，d56f69e）：`_post_analyze_learning` 加 batch 参数，两条路径统一。

### 现状与问题

`analyze()` 里有两条高风险评估路径：

- `evaluate_result()`（agent.py:386，非 batch 高风险）——有 P0-1 的 bug，做 assess+apply+评估+记忆；
- `_evaluate_critical()`（agent.py:856，batch 模式高/严重）——只写一条记忆。

语义重叠、行为不一致（同为高风险分析，batch 与非 batch 的学习结果不同）。

### 修改方案

1. 完成 P0-1 后，把 `_evaluate_critical` 并入 `evaluate_result`：batch 模式走 `interactive=False + confirm_fn=None + 跳过技能创建` 的同一条路径。
2. `analyze()` 中两个调用点统一为一个，按 `batch` 传参区分。

### 验收标准

- 单测：batch 与非 batch 高风险分析，memory 写入结果一致（除技能创建外）。

---

## P2-5 README 补 `secagent eval` 文档

> ✅ 已完成（v0.10.0，9c9b72b + 0ef1047）：子命令表 + 评估小节 + fixture 机制说明。

### 现状

`cli.py:1694` 已有 `eval` 子命令（--dataset/--online/--save-baseline/--check-baseline），但 README 子命令列表（110-133 行）和功能特性（37-52 行）均未提及。

### 修改方案

README 子命令表加一行，并新增"## 分析质量评估"小节：用法、回放/在线模式区别、baseline 工作流、`tests/eval/dataset.yaml` 标注规范。

### 验收标准

- `secagent eval --help` 输出与 README 一致。


---

## P3-1 GitHub Actions CI

> ❌ 未实现：`.github/workflows/` 尚不存在。实施时注意：P1-1 已就位，
> `python -m secagent eval --check-baseline` 步骤可以直接纳入（依赖 baseline.json 先生成入库）。

### 修改方案

`.github/workflows/test.yml`：

```yaml
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        python: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "${{ matrix.python }}" }
      - run: pip install -e ".[dev]"
      - run: python -m pytest tests/ -q
      # P1-1 就位后追加：
      # - run: python -m secagent eval --check-baseline
```

### 验收标准

- PR 上能看到检查状态；baseline 检查在 P1-1 后接入。

---

## P3-2 server.py API 鉴权

> ❌ 未实现：`secagent serve` 仍无鉴权，绑定非 loopback 地址时无告警。

### 现状与问题

`secagent serve --host 0.0.0.0` 后任何人可调用 `/analyze` 消耗 LLM/MCP 配额，也可读 `/history`（含敏感分析内容）。

### 修改方案

- `config.py` 新增 `serve.api_key`（默认空 = 仅 loopback 可用）。
- FastAPI middleware：非 loopback 来源且配置了 api_key 时校验 `Authorization: Bearer <key>`；未配置 key 且绑定非 loopback 地址时启动告警。

### 验收标准

- 单测：无 key + 0.0.0.0 → 启动 warning；有 key → 401/200 行为正确。

---

## P3-3 评估数据集扩充

> ❌ 未实现（持续项）：`tests/eval/dataset.yaml` 当前 6 条样本（2 malicious + benign/borderline），
> 且 6 个 fixture 均待生成（见 P1-1 遗留）。扩样时每条需同步配 fixture。

`tests/eval/dataset.yaml` 当前仅 6 条样本（2 malicious + benign/borderline），统计意义弱。随真实分析积累，按 ROADMAP 的分类（malicious/benign/borderline）扩到 20+，每条配 P1-1 的 fixture。此项持续进行，不设截止。

---

## 附录 A：上期 ROADMAP 完成状态核对（v0.9.2 实测）

| ROADMAP 项 | 状态 | 证据 |
|------------|------|------|
| P1-1 per-server 结构化解析层 | ✅ 已完成（v0.9.1） | `secagent/parsers/`（ctia/fdp/generic），信号带来源 |
| P1-2 IOC 校验与结构化 | ✅ 已完成（v0.9.1） | `result_parser.py:562 validate_iocs`，verified/unverified 分组 |
| P1-3 工具去重与路由 | ❌ 未实现 → 本文 P1-2 | grep 无 `tool_routing` |
| P1-4 评估框架 | ⚠️ 已实现但有设计缺陷 → 本文 P1-1 修正 | `eval.py` 回放依赖最终结果缓存 |
| P2-1 数据源覆盖度报告 | ✅ 已完成（v0.9.1） | `AnalysisResult.coverage` + CLI 展示 + 置信度压低 |
| P2-2 相似案例检索注入 | ❌ 未实现 → 本文 P2-2 | grep 无相关逻辑 |
| P2-3 web_fetch 内容信任边界 | ✅ 已完成（v0.9.0） | `<untrusted_web_content>` 包裹 + prompt 声明 |
| P2-4 成本预算护栏 | ❌ 未实现 → 本文 P2-1 | grep 无 `budget` |
| P2-5 结构化最终输出 | ❌ 未实现 → 本文 P1-3 | `response_format` 仅 salvage 路径使用 |

## 附录 B：里程碑与实际发版

原计划分四次发版，实际 P0/P1/P2 内容未单独发版，合并为 v0.10.0（c5309ac）一次发布：

| 版本 | 内容 | 状态 |
|------|------|------|
| ~~v0.9.3~~ | P0-1 ~ P0-4（bug 修复包） | ✅ 并入 v0.10.0 |
| v0.10.0 | P1-1 + P1-2 + P1-3 + P0 + P2 全部 | ✅ 已发布（c5309ac，251 测试全绿） |
| ~~v0.10.1~~ | P1-2 + P1-3（成本与健壮性） | ✅ 并入 v0.10.0 |
| ~~v0.11.0~~ | P2-1 ~ P2-5（完善包） | ✅ 并入 v0.10.0 |
| v0.11.0（规划） | P3-1 CI + P3-2 serve 鉴权 | ❌ 未开始；CI 的 baseline 步骤依赖 fixture/baseline 先生成 |
| 持续 | P3-3 数据集扩充 + fixture/baseline 生成 | ❌ 未开始，需真实 API 配额 |

