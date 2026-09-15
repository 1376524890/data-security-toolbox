"""Detection-engine adapter for passive network DLP analysis."""

from app.engine.core.base import DetectionEngine
from app.engine.core.result import DetectionResult
from app.services.dlp_service import DEFAULT_POLICY, analyze_capture


class DlpEngine(DetectionEngine):
    name = "dlp_engine"
    version = "2.4.0"

    def analyze(self, context):
        config = context.data.get("dlp_policy", DEFAULT_POLICY)
        if not config.get("enabled", True) or context.target_type != "pcap" or not context.path:
            return []
        result, observations, finding_rows = analyze_capture(context.path, config)
        context.data["dlp"] = result
        context.data["transfer_observations"] = {key: sorted(values) for key, values in observations.items()}
        return [DetectionResult(**item).normalize() for item in finding_rows]
