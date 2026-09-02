"""Integration Adapter Layer for third-party security components."""

from app.integrations.base import AdapterResult, IntegrationAdapter
from app.integrations.registry import integration_registry

__all__ = ["AdapterResult", "IntegrationAdapter", "integration_registry"]
