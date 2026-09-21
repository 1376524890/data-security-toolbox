"""Limits and the built-in fallback policy of the passive network DLP path.

Every bound here is a resource guard, not a detection decision: a capture that
hits one is analysed partially and reported as incomplete coverage, never as
proof that nothing left the host.
"""
from app.rules.library import rule_policy
from app.services.rule_library import MIN_ALERT_CONFIDENCE

MAX_STREAM = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_STREAMS = 256
MAX_PACKETS = 200000
MAX_OBJECTS = 500
# Built-in fallback, used only when the DLP rule file is absent from the library.
BUILTIN_DEFAULT_POLICY = {'enabled': True, 'categories': ['phone', 'id_card', 'email', 'api_key'],
                          'keywords': [], 'fingerprints': [], 'min_matches': 1,
                          'min_confidence': MIN_ALERT_CONFIDENCE,
                          'exclude_cidrs': ['127.0.0.0/8', '::1/128'],
                          # The toolbox talking to itself is not data loss.
                          'self_endpoints': [], 'ignore_own_traffic': True}
# The default policy the engine applies is the DLP rule in the platform
# library (app/rules/dlp), so the rule an operator tunes and the policy the
# engine runs are one document instead of two drifting copies.
DEFAULT_POLICY = rule_policy('dlp_engine', 'DLP_TRANSFER_001', BUILTIN_DEFAULT_POLICY)
# Our own management channel authenticates with fixed header/cookie names, so a
# captured stream carrying them is the toolbox talking to itself no matter which
# address it uses (platform URL, DHCP change, hostname vs IP, ...).
OWN_TRAFFIC_MARKERS = (b'x-probe-token', b'x-probe-id', b'x-probe-bootstrap-token')
# Precision of the built-in patterns. ``token`` matches any long random run, so
# hashes, base64 blobs and container ids keep it below the alert threshold.
BUILTIN_CONFIDENCE = {'phone': .7, 'id_card': .9, 'bank_card': .85, 'email': .85, 'api_key': .95, 'token': .3}
