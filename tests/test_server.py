"""测试 server.py：P3-2 API 鉴权（loopback 判断 + Bearer token 校验）。

依赖 fastapi/uvicorn（运行时依赖）；本地未安装时自动跳过（CI 会安装后运行）。
"""

import pytest

fastapi = pytest.importorskip("fastapi")

import io  # noqa: E402
from contextlib import redirect_stdout  # noqa: E402
from unittest import mock  # noqa: E402

from secagent.server import _check_auth, _is_loopback  # noqa: E402


class TestIsLoopback:
    def test_loopback_hosts(self):
        for h in ("127.0.0.1", "localhost", "::1"):
            assert _is_loopback(h)

    def test_public_hosts(self):
        for h in ("0.0.0.0", "192.168.1.10", "10.0.0.2", "185.199.108.153"):
            assert not _is_loopback(h)

    def test_invalid_host(self):
        assert not _is_loopback("not-an-ip")


def _fake_req(auth_header: str | None):
    """构造最小 Request mock。"""
    return mock.Mock(
        headers={"authorization": auth_header} if auth_header else {}
    )


class TestCheckAuth:
    def test_loopback_skips_auth(self):
        # loopback host 且无 key 也不校验
        _check_auth(_fake_req(None), api_key="secret", host="127.0.0.1")

    def test_no_key_skips_auth(self):
        # 空 key 时不校验（任何 host）
        _check_auth(_fake_req(None), api_key="", host="0.0.0.0")

    def test_correct_bearer_allowed(self):
        _check_auth(_fake_req("Bearer my-secret-key"), api_key="my-secret-key",
                    host="0.0.0.0")

    def test_missing_bearer_rejected(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _check_auth(_fake_req(None), api_key="secret", host="0.0.0.0")
        assert ei.value.status_code == 401

    def test_wrong_scheme_rejected(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _check_auth(_fake_req("Basic dXNlcjpwYXNz"), api_key="secret",
                        host="0.0.0.0")
        assert ei.value.status_code == 401

    def test_wrong_token_rejected(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _check_auth(_fake_req("Bearer wrong"), api_key="secret",
                        host="0.0.0.0")
        assert ei.value.status_code == 401


class TestCreateAppWarning:
    def _call_create_app(self, host, api_key):
        """调用 create_app，返回 (stdout, app)。"""
        from secagent.server import create_app
        with mock.patch("secagent.agent.SecurityAgent") as AgentCls, \
             mock.patch("secagent.server.load_config") as load_cfg:
            cfg = mock.MagicMock()
            cfg.serve_api_key = api_key
            cfg.max_iterations = 20
            load_cfg.return_value = cfg
            AgentCls.return_value = mock.MagicMock()
            buf = io.StringIO()
            with redirect_stdout(buf):
                app = create_app(host=host)
        return buf.getvalue(), app

    def test_public_host_no_key_warns(self):
        """绑定非 loopback 且无 key → 启动告警。"""
        out, _ = self._call_create_app("0.0.0.0", "")
        assert "警告" in out
        assert "API key" in out

    def test_loopback_no_warning(self):
        """绑定 loopback 时即使无 key 也不告警。"""
        out, _ = self._call_create_app("127.0.0.1", "")
        assert "警告" not in out

    def test_public_host_with_key_no_warning(self):
        """绑定非 loopback 但有 key → 不告警（启用鉴权）。"""
        out, _ = self._call_create_app("0.0.0.0", "secret-token")
        assert "警告" not in out

