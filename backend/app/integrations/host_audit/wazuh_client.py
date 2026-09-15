from __future__ import annotations

from typing import Any

import requests


class WazuhClientError(RuntimeError):
    """Raised when the Wazuh API cannot be reached or returns an error."""


class WazuhClient:
    """Minimal Wazuh 4.x REST API client (login + alert ingestion).

    Endpoints used:
      - POST /security/user/authenticate  (HTTP Basic auth -> bearer token)
      - GET  /alerts                       (most recent alerts, newest first)
    """

    def __init__(self, url: str, username: str, password: str, verify_ssl: bool = True, timeout: int = 30) -> None:
        self.url = (url or "").rstrip("/")
        self.username = username or ""
        self.password = password or ""
        self.verify_ssl = bool(verify_ssl)
        self.timeout = timeout
        self.token = ""

    def login(self) -> str:
        if not self.url or not self.username:
            raise WazuhClientError("Wazuh URL and credentials are required")
        try:
            response = requests.post(
                f"{self.url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()
            token = response.json().get("data", {}).get("token")
        except requests.RequestException as exc:
            raise WazuhClientError(f"Wazuh API unreachable: {exc}") from exc
        except ValueError as exc:
            raise WazuhClientError("Wazuh login returned invalid JSON") from exc
        if not token:
            raise WazuhClientError("Wazuh login did not return a token")
        self.token = token
        return token

    def _headers(self) -> dict[str, str]:
        if not self.token:
            self.login()
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    def fetch_alerts(self, limit: int = 200, start: str = "") -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": max(1, int(limit)), "sort": "-timestamp"}
        if start:
            params["q"] = f"timestamp>{start}"
        try:
            response = requests.get(
                f"{self.url}/alerts",
                params=params,
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise WazuhClientError(f"Wazuh alerts fetch failed: {exc}") from exc
        except ValueError as exc:
            raise WazuhClientError("Wazuh alerts returned invalid JSON") from exc
        data = payload.get("data", payload) if isinstance(payload, dict) else payload
        items = data.get("items", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            items = []
        return [item for item in items if isinstance(item, dict)]

    def health(self) -> dict[str, Any]:
        try:
            self.login()
            return {"reachable": True, "authenticated": True, "message": ""}
        except WazuhClientError as exc:
            return {"reachable": False, "authenticated": False, "message": str(exc)[:300]}