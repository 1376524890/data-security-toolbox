"""Plugin detection engines."""

from app.engine.asset_engine.engine import AssetEngine
from app.engine.compliance_engine.engine import ComplianceEngine
from app.engine.core.registry import EngineRegistry
from app.engine.data_engine.engine import DataEngine
from app.engine.log_engine import SigmaLogEngine
from app.engine.protocol_engine.engine import ProtocolEngine
from app.engine.traffic_engine.engine import TrafficEngine
from app.integrations.engine import IntegrationAdapterEngine
from app.integrations.registry import integration_registry
from app.threat_intel.engine import ThreatIntelEngine

registry = EngineRegistry()
registry.register(AssetEngine())
registry.register(ProtocolEngine())
registry.register(TrafficEngine())
registry.register(DataEngine())
registry.register(SigmaLogEngine())
registry.register(ComplianceEngine())
registry.register(ThreatIntelEngine())
for adapter in integration_registry.all():
    registry.register(IntegrationAdapterEngine(adapter))
