# 评估 fixture 生成与入库指南

本文说明如何生成 `secagent eval` 回放评估所需的 fixture，并形成"离线、无 token 可复现"
的回归基线。看完本指南，你就知道为什么 CI 不需要 token 也能验证分析逻辑。

---

## 背景：为什么需要 fixture

- **在线模式**（`--online`）真实调用 LLM + MCP server，消耗配额，且结果受真实数据/时间影响，不可复现。
- **回放模式**（默认）用 `tests/eval/fixtures/<target>.json` 里存档的**工具返回快照**替代真实 MCP，
  LLM、信号提取、双轨评分全部走**当前代码**。
- 因此回放能在**无 token、零成本**环境下，验证"同样一批真实数据下，代码改动是否改善/恶化分析"。

> 与旧缓存方案的本质区别：fixture 存的是**工具返回（中间数据）**而非**最终结论**，
> 所以 prompt / 评分权重改动会直接反映在回放结果里，具备回归能力。

---

## 一、首次生成 fixture（需真实 token，在 CI 外本机跑一次）

对 `tests/eval/dataset.yaml` 中每一条样本真实分析一次，并把工具返回存成 fixture：

```bash
# 在线跑评估，同时把每样本的工具返回写入 tests/eval/fixtures/<target>.json
secagent eval --dataset tests/eval/dataset.yaml --online --save-fixtures
```

- 生成位置：`tests/eval/fixtures/<target>.json`（文件名默认取样本的 `fixture` 字段或 `<target>.json`）
- 生成后，把这些 fixture 文件**提交入库**（纳入 git），这样 CI / 其他开发者可直接回放。
- 若只想单个样本，可临时写一个只含一条样本的 YAML 传入 `--dataset`。

### fixture 文件内容示例

```json
{
  "target": "baidu.com",
  "target_type": "domain",
  "tool_calls": [
    {"tool": "ctia_domain__v1_domain", "args": {"domain": "baidu.com"},
     "content": "{\"risk\": \"低\", ...}"},
    {"tool": "hunter__search", "args": {"query": "baidu.com"}, "content": "..."}
  ]
}
```

它就是"该目标当时真实的威胁情报快照"，供回放时代替真实 MCP 返回。

---

## 二、回放评估（无 token，CI / 本地通用）

所有 fixture 入库后，任意环境（包括 CI）可做离线评估：

```bash
# 回放模式（默认）：读 fixture 回放，无 fixture 的样本标记 SKIP
secagent eval --dataset tests/eval/dataset.yaml

# 纯离线冒烟：用脚本化假 LLM，实测无需任何 LLM/MCP 配额（零成本，快速）
SECAGENT_EVAL_FAKE_LLM=1 secagent eval --dataset tests/eval/dataset.yaml
```

> 注意：即使有 fixture，默认回放仍会调**真实 LLM** 生成结论（工具数据离线，LLM 在线）。
> 想完全离线，务必设置 `SECAGENT_EVAL_FAKE_LLM=1`。

---

## 三、建立并维护回归基线

1. **首次建立基线**（需有 token 或已离线回放过一次）：
   ```bash
   secagent eval --dataset tests/eval/dataset.yaml --save-baseline
   # 写入 tests/eval/baseline.json，建议提交入库
   ```
2. **代码改动后检查退化**：
   ```bash
   secagent eval --dataset tests/eval/dataset.yaml --check-baseline
   ```
   对比命中率 / 误报 / 漏报是否退化，退化会列出具体项。

3. **CI 自动回归**（`test.yml` 已含此步）：
   只要 `tests/eval/baseline.json` 已入库且 fixtures 齐全，push/PR 时 CI 会自动执行
   `eval --check-baseline`，防止核心指标回归。

> **推荐工作流**：改动 prompt / 评分逻辑前先 `--save-baseline`，改动后 `--check-baseline`，
> 确认无退化再提交。

---

## 四、扩充数据集时的配套步骤

每新增一条样本到 `tests/eval/dataset.yaml`，应同步：

1. 在样本里写 `fixture: "<target>.json"`（或留空，默认用 `<target>.json`）。
2. 用 `--online --save-fixtures` 生成对应 fixture。
3. 把新 fixture 提交入库。

这样数据集扩了几条，回放评估就能覆盖几条，无需额外 token。

---

## 常见问题

**Q：回放时提示"无 baseline，首次运行请用 --save-baseline"？**
说明 `baseline.json` 尚未生成或未入库。先 `--save-baseline` 并提交。

**Q：某些样本在回放中标记 SKIP？**
说明该样本的 fixture 文件缺失（未生成或未入库）。用 `--online --save-fixtures` 补齐。

**Q：CI 的 baseline 步骤会失败吗？**
不会。`test.yml` 先判断 `tests/eval/baseline.json` 是否存在——不存在则打印提示并跳过，
只有存在才执行 `--check-baseline`。所以未生成基线前 CI 不影响。
