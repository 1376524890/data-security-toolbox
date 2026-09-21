"""Passive network DLP: policy, capture parsing and the detection stage.

Layering (dependencies point down, never back up):

    constants  <-  policy / self_traffic / capture  <-  detect

``detect`` is the only module that holds both a capture and a policy; it is the
only one that reaches the rule store and the shared sensitive engine. Changing
which rules run therefore never means reading packet reassembly, and changing
how packets are read never means reading the rule store.
"""
from app.services.dlp.capture import dechunk, http_objects, looks_like_text, reassemble
from app.services.dlp.constants import (
                                        BUILTIN_CONFIDENCE,
                                        BUILTIN_DEFAULT_POLICY,
                                        DEFAULT_POLICY,
                                        MAX_OBJECTS,
                                        MAX_PACKETS,
                                        MAX_STREAM,
                                        MAX_STREAMS,
                                        MAX_TOTAL,
                                        OWN_TRAFFIC_MARKERS,
)
from app.services.dlp.detect import (
                                        analyze_capture,
                                        build_finding,
                                        inspect_content,
                                        object_metadata,
                                        store_object_bytes,
                                        stream_objects,
)
from app.services.dlp.policy import alertable, excluded_networks, host_internal, normalize_policy
from app.services.dlp.self_traffic import (
                                        endpoint_is_self,
                                        host_header_is_self,
                                        is_own_traffic,
                                        own_traffic_markers,
                                        parse_self_endpoints,
                                        self_endpoint_entries,
)

__all__ = [
    "BUILTIN_CONFIDENCE",
    "BUILTIN_DEFAULT_POLICY",
    "DEFAULT_POLICY",
    "MAX_OBJECTS",
    "MAX_PACKETS",
    "MAX_STREAM",
    "MAX_STREAMS",
    "MAX_TOTAL",
    "OWN_TRAFFIC_MARKERS",
    "alertable",
    "analyze_capture",
    "build_finding",
    "dechunk",
    "endpoint_is_self",
    "excluded_networks",
    "host_header_is_self",
    "host_internal",
    "http_objects",
    "inspect_content",
    "is_own_traffic",
    "looks_like_text",
    "normalize_policy",
    "object_metadata",
    "own_traffic_markers",
    "parse_self_endpoints",
    "reassemble",
    "self_endpoint_entries",
    "store_object_bytes",
    "stream_objects",
]
