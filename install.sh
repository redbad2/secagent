#!/usr/bin/env bash
# secagent 一键安装脚本
# 用法: bash install.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SECAGENT_HOME="${SECAGENT_HOME:-$HOME/.secagent}"
VERSION=$(grep '__version__' "$REPO_DIR/secagent/__init__.py" | cut -d'"' -f2)

echo "╔══════════════════════════════════════╗"
echo "║   secagent 安装程序 v${VERSION}          ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. 检查 Python
if ! command -v python3 &>/dev/null; then
    echo "错误: 未找到 python3，请先安装 Python 3.10+"
    exit 1
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Python: $PY_VERSION"

if [[ "$PY_VERSION" < "3.10" ]]; then
    echo "错误: 需要 Python 3.10+，当前 $PY_VERSION"
    exit 1
fi

# 2. 检查 uv (可选，推荐)
if command -v uv &>/dev/null; then
    echo "uv: $(uv --version)"
    USE_UV=1
else
    echo "uv: 未安装 (使用 venv 代替)"
    USE_UV=0
fi

# 3. 创建虚拟环境
VENV_DIR="$REPO_DIR/.venv"
echo ""
echo "创建虚拟环境: $VENV_DIR"
if [[ "$USE_UV" == "1" ]]; then
    uv venv "$VENV_DIR"
else
    python3 -m venv "$VENV_DIR"
fi

# 4. 安装依赖
echo ""
echo "安装依赖..."
if [[ "$USE_UV" == "1" ]]; then
    uv pip install --python "$VENV_DIR/bin/python" -e "$REPO_DIR"
else
    "$VENV_DIR/bin/pip" install -e "$REPO_DIR"
fi

# 5. 创建 secagent home
echo ""
echo "创建配置目录: $SECAGENT_HOME"
mkdir -p "$SECAGENT_HOME"/{skills,memory,logs}

# 6. 复制预置技能
if [[ -d "$REPO_DIR/skills" ]]; then
    cp -r "$REPO_DIR/skills/"* "$SECAGENT_HOME/skills/" 2>/dev/null || true
    echo "已复制预置技能到 $SECAGENT_HOME/skills/"
fi

# 7. 创建默认配置（如果不存在）
CONFIG_FILE="$SECAGENT_HOME/config.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    if [[ -f "$REPO_DIR/config.template.yaml" ]]; then
        cp "$REPO_DIR/config.template.yaml" "$CONFIG_FILE"
        echo "已从模板创建配置: $CONFIG_FILE"
    else
        cat > "$CONFIG_FILE" << 'YAML'
# secagent 配置
llm:
  base_url: "https://api.deepseek.com/v1"
  api_key: ""
  model: "deepseek-chat"

agent:
  max_iterations: 20
  timeout: 300
YAML
        echo "已创建默认配置: $CONFIG_FILE"
    fi
    echo ""
    echo "⚠️  请编辑 $CONFIG_FILE 填入 API key"
else
    echo "配置已存在，跳过: $CONFIG_FILE"
fi

# 8. 创建 .env 模板（如果不存在）
ENV_FILE="$SECAGENT_HOME/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" << 'ENV'
# secagent 环境变量（可选，优先级低于 config.yaml）
# 取消注释并填入值即可使用

# DEEPSEEK_API_KEY=sk-xxx
# FDP_ACCESS_KEY=xxx
# FDP_SECRET_KEY=xxx
# CTIA_TOKEN=xxx
# MCP_HUNTER_MCP_API_KEY=Bearer xxx
# EXA_API_KEY=xxx
ENV
    echo "已创建环境变量模板: $ENV_FILE"
fi

# 9. 创建可执行脚本
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/secagent" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" -m secagent "\$@"
EOF
chmod +x "$BIN_DIR/secagent"

echo ""
echo "✅ 安装完成!"
echo ""
echo "  可执行文件: $BIN_DIR/secagent"
echo "  配置文件:   $CONFIG_FILE"
echo "  环境变量:   $ENV_FILE"
echo "  技能目录:   $SECAGENT_HOME/skills/"
echo ""
echo "下一步:"
echo "  1. 编辑配置文件填入 API key:"
echo "     vim $CONFIG_FILE"
echo ""
echo "  2. 确保 ~/.local/bin 在 PATH 中:"
echo "     export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
echo "  3. 运行:"
echo "     secagent analyze example.com"
echo "     secagent              # 交互式模式"
