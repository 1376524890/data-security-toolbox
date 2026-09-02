from __future__ import annotations

from typing import Any

from app.integrations.base import IntegrationAdapter


class IntegrationRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, IntegrationAdapter] = {}

    def register(self, adapter: IntegrationAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> IntegrationAdapter:
        if name not in self._adapters:
            raise KeyError(f"unknown integration adapter: {name}")
        return self._adapters[name]

    def all(self) -> list[IntegrationAdapter]:
        return list(self._adapters.values())

    def metadata(self) -> list[dict[str, Any]]:
        return [{**item.metadata(), **item.health()} for item in self.all()]


integration_registry = IntegrationRegistry()


def _register_adapters() -> None:
    from app.integrations.host_audit.osquery_adapter import OsqueryAdapter
    from app.integrations.host_audit.wazuh_adapter import WazuhAdapter
    from app.integrations.misp.adapter import MISPAdapter
    from app.integrations.openscap.adapter import OpenSCAPAdapter
    from app.integrations.presidio.adapter import PresidioAdapter
    from app.integrations.suricata.adapter import SuricataAdapter
    from app.integrations.zeek.adapter import ZeekAdapter

    for adapter in (
        ZeekAdapter(),
        SuricataAdapter(),
        PresidioAdapter(),
        MISPAdapter(),
        OsqueryAdapter(),
        WazuhAdapter(),
        OpenSCAPAdapter(),
    ):
        integration_registry.register(adapter)


_register_adapters()
