"""Compatibility facade for the passive network DLP domain.

The implementation moved to ``app.services.dlp`` (``constants`` / ``policy`` /
``self_traffic`` / ``capture`` / ``detect``) so a policy change no longer has to
be read together with packet reassembly. This module only re-exports the names
existing callers and regression tests import; new code imports
``app.services.dlp`` directly.
"""
from app.services.dlp import (
                              BUILTIN_CONFIDENCE,
                              DEFAULT_POLICY,
                              MAX_OBJECTS,
                              MAX_PACKETS,
                              MAX_STREAM,
                              MAX_STREAMS,
                              MAX_TOTAL,
                              OWN_TRAFFIC_MARKERS,
                              alertable,
                              analyze_capture,
                              dechunk,
                              endpoint_is_self,
                              excluded_networks,
                              host_header_is_self,
                              host_internal,
                              http_objects,
                              inspect_content,
                              is_own_traffic,
                              looks_like_text,
                              normalize_policy,
                              own_traffic_markers,
                              parse_self_endpoints,
                              reassemble,
                              self_endpoint_entries,
)
from app.services.masking import masked

__all__ = [
    "BUILTIN_CONFIDENCE",
    "DEFAULT_POLICY",
    "MAX_OBJECTS",
    "MAX_PACKETS",
    "MAX_STREAM",
    "MAX_STREAMS",
    "MAX_TOTAL",
    "OWN_TRAFFIC_MARKERS",
    "alertable",
    "analyze_capture",
    "dechunk",
    "endpoint_is_self",
    "excluded_networks",
    "host_header_is_self",
    "host_internal",
    "http_objects",
    "inspect_content",
    "is_own_traffic",
    "looks_like_text",
    "masked",
    "normalize_policy",
    "own_traffic_markers",
    "parse_self_endpoints",
    "reassemble",
    "self_endpoint_entries",
]
