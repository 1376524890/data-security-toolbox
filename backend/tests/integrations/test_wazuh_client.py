from unittest.mock import MagicMock, patch

import pytest

from app.integrations.host_audit.wazuh_adapter import WazuhAdapter
from app.integrations.host_audit.wazuh_client import WazuhClient, WazuhClientError


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._payload


def test_client_login_returns_token() -> None:
    with patch("requests.post", return_value=_FakeResponse({"data": {"token": "abc123"}})) as mock:
        client = WazuhClient("https://wazuh:55000", "admin", "secret")
        token = client.login()
    assert token == "abc123"
    assert client.token == "abc123"
    mock.assert_called_once()
    assert mock.call_args[0][0].endswith("/security/user/authenticate")


def test_client_fetch_alerts() -> None:
    items = [{"timestamp": "2026-01-01T00:00:00Z", "rule": {"id": 100001, "level": 13, "description": "rootkit"}}]
    with patch("requests.post", return_value=_FakeResponse({"data": {"token": "t"}})), \
         patch("requests.get", return_value=_FakeResponse({"data": {"items": items}})) as mock:
        client = WazuhClient("https://wazuh:55000", "admin", "secret")
        records = client.fetch_alerts(limit=10)
    assert records == items
    assert mock.call_args[0][0].endswith("/alerts")


def test_client_fetch_rejects_unconfigured() -> None:
    client = WazuhClient("", "", "")
    with pytest.raises(WazuhClientError):
        client.login()


def test_adapter_health_unavailable_when_not_configured() -> None:
    health = WazuhAdapter().health()
    assert health["status"] == "unavailable"
    assert health["healthy"] is False


def test_adapter_sync_pulls_and_scores() -> None:
    adapter = WazuhAdapter()
    with patch.object(adapter, "fetch", return_value=[
        {"timestamp": "2026-01-01T00:00:00Z", "rule": {"id": 100001, "level": 13, "description": "rootkit"}},
    ]):
        result = adapter.adapt({"sync": True})
    assert result.records
    assert any(item.rule_id == "WAZUH_100001" for item in result.findings)