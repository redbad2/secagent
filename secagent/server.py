"""API 服务化：用 FastAPI 提供 HTTP API，让 secagent 可被其他系统调用。

用法：
    secagent serve                    # 默认 127.0.0.1:8000
    secagent serve --host 0.0.0.0 --port 9000

端点：
    POST /analyze   - 分析目标，返回 AnalysisResult.to_dict()
    POST /batch     - 批量分析，返回结果列表
    GET  /history   - 查询历史会话
    GET  /monitor/list - 查看监控目标
    POST /monitor/run - 触发监控扫描
    GET  /status    - MCP 服务器健康状态
    GET  /version   - 版本信息

鉴权（P3-2）：
    绑定 loopback（127.0.0.1/localhost/::1）时免认证。
    绑定非 loopback 地址时，必须设置 SECAGENT_SERVE_API_KEY 环境变量
    或 config.yaml 的 serve.api_key，所有请求需带 Authorization: Bearer <key>；
    未配置 key 绑定非 loopback 地址时仅打印启动告警。
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from secagent.config import load_config
from secagent.result_parser import detect_target_type

logger = logging.getLogger(__name__)


def _is_loopback(host: str) -> bool:
    """判断监听地址是否为本机回环地址。"""
    if host in ("127.0.0.1", "localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def _check_auth(req: Request, api_key: str, host: str) -> None:
    """校验请求鉴权。loopback 来源免认证；否则校验 Authorization: Bearer <key>。"""
    if _is_loopback(host) or not api_key:
        return
    scheme, _, token = req.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="缺少 Bearer token")
    # 常量时间比较，防时序侧信道
    if not hmac.compare_digest(token.strip(), api_key):
        raise HTTPException(status_code=401, detail="无效的 API key")


def create_app(host: str = "127.0.0.1") -> FastAPI:
    """创建 FastAPI 应用实例。host 用于判断是否需要鉴权。"""
    from secagent.agent import SecurityAgent

    config = load_config()
    if config.max_iterations < 15:
        config.max_iterations = 20

    # 鉴权配置（P3-2）
    api_key = config.serve_api_key
    if not _is_loopback(host) and not api_key:
        print(
            f"\n  [警告] serve 绑定非 loopback 地址 {host} 但未配置 API key，"
            "任何可访问该端口的人都可调用分析接口。\n"
            "  建议设置 SECAGENT_SERVE_API_KEY 环境变量或在 config.yaml 配置 serve.api_key。\n"
        )

    app = FastAPI(title="secagent API", description="CLI 安全分析 Agent HTTP API")
    agent = SecurityAgent(config)

    @app.middleware("http")
    async def auth_middleware(req: Request, call_next):
        """全局鉴权：非 loopback 且配置了 key 时校验 Bearer token。"""
        _check_auth(req, api_key, host)
        return await call_next(req)

    @app.on_event("startup")
    async def startup():
        """启动时连接所有 MCP server（不区分 target_type）。"""
        await agent.connect()

    # ------------------------------------------------------------------
    # 请求模型
    # ------------------------------------------------------------------

    class AnalyzeRequest(BaseModel):
        target: str
        depth: str = "standard"

    class BatchRequest(BaseModel):
        targets: list[str]
        depth: str = "quick"

    # ------------------------------------------------------------------
    # 端点
    # ------------------------------------------------------------------

    @app.post("/analyze")
    async def analyze(req: AnalyzeRequest) -> dict[str, Any]:
        """分析单个目标。"""
        if not req.target.strip():
            raise HTTPException(status_code=400, detail="target 不能为空")
        target_type = detect_target_type(req.target)
        try:
            result = await agent.analyze(
                req.target, depth=req.depth, interactive=False, batch=True,
            )
            return result.to_dict()
        except Exception as e:
            logger.exception("API /analyze 失败")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/batch")
    async def batch(req: BatchRequest) -> list[dict[str, Any]]:
        """批量分析。"""
        if not req.targets:
            raise HTTPException(status_code=400, detail="targets 不能为空")
        semaphore = asyncio.Semaphore(3)
        results: list[dict[str, Any]] = []

        async def _one(t: str):
            async with semaphore:
                try:
                    result = await agent.analyze(
                        t, depth=req.depth, interactive=False, batch=True,
                    )
                    return {"target": t, "risk_level": result.risk_level,
                            "summary": result.summary}
                except Exception as e:
                    return {"target": t, "risk_level": "错误", "summary": str(e)[:100]}

        try:
            tasks = [_one(t) for t in req.targets]
            results = await asyncio.gather(*tasks)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        return list(results)

    @app.get("/history")
    async def history(target: str = "", limit: int = 20) -> list[dict[str, Any]]:
        """查询历史会话。"""
        if target:
            data = agent.sessions.get_session(target)
            return [data] if data else []
        return agent.sessions.list_recent(limit=limit)

    @app.get("/monitor/list")
    async def monitor_list() -> list[dict[str, Any]]:
        """查看监控目标。"""
        from secagent.monitor import MonitorDB
        db = MonitorDB(config.secagent_home)
        targets = db.list_targets()
        db.close()
        return targets

    @app.post("/monitor/run")
    async def monitor_run(depth: str = "quick") -> dict[str, Any]:
        """触发监控扫描，返回变化列表。"""
        from secagent.monitor import MonitorDB
        db = MonitorDB(config.secagent_home)
        targets = db.get_enabled_targets()
        if not targets:
            db.close()
            return {"changes": [], "total": 0}

        changes = []
        semaphore = asyncio.Semaphore(3)

        async def _scan(t: str):
            async with semaphore:
                try:
                    result = await agent.analyze(
                        t, depth=depth, interactive=False, batch=True,
                    )
                    changed = db.save_snapshot(
                        t, result.risk_level, result.summary or "", result.findings or [],
                    )
                    if changed:
                        changes.append({
                            "target": t, "risk_level": result.risk_level,
                            "summary": result.summary,
                        })
                except Exception as e:
                    logger.warning("监控扫描 %s 失败: %s", t, e)

        try:
            await asyncio.gather(*[_scan(t) for t in targets])
        finally:
            await agent.disconnect()
        db.close()
        return {"changes": changes, "total": len(targets)}

    @app.get("/status")
    async def status() -> dict[str, Any]:
        """MCP 服务器健康状态。"""
        if not agent.mcp._connected:
            return {"connected": False, "servers": {}}
        results = await agent.mcp.health_check()
        return {"connected": True, "servers": results}

    @app.get("/version")
    async def version() -> dict[str, str]:
        """版本信息。"""
        from secagent import __version__
        return {"version": __version__}

    @app.on_event("shutdown")
    async def shutdown():
        try:
            await agent.disconnect()
        except Exception:
            pass
        agent.close()

    return app


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """启动 API 服务器。"""
    import uvicorn
    app = create_app(host=host)
    print(f"\n  secagent API 服务启动: http://{host}:{port}")
    print(f"  文档: http://{host}:{port}/docs\n")
    uvicorn.run(app, host=host, port=port)
