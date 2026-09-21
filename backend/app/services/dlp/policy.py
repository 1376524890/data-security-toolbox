"""Which transfers this deployment cares about, and where they may go."""
import ipaddress

from app.rules.library import rule_policy
from app.services.dlp.constants import BUILTIN_DEFAULT_POLICY, DEFAULT_POLICY
from app.services.rule_library import DEFAULT_CONFIDENCE, MIN_ALERT_CONFIDENCE


def normalize_policy(config):
    """Fill policy defaults so stored policies written before a key existed stay usable."""
    policy = {**rule_policy('dlp_engine', 'DLP_TRANSFER_001', BUILTIN_DEFAULT_POLICY),
              **(config or {})}
    try:
        policy['min_matches'] = max(1, int(policy['min_matches']))
    except (TypeError, ValueError):
        policy['min_matches'] = DEFAULT_POLICY['min_matches']
    try:
        policy['min_confidence'] = min(1.0, max(0.0, float(policy['min_confidence'])))
    except (TypeError, ValueError):
        policy['min_confidence'] = MIN_ALERT_CONFIDENCE
    if not isinstance(policy.get('exclude_cidrs'), list):
        policy['exclude_cidrs'] = list(DEFAULT_POLICY['exclude_cidrs'])
    if not isinstance(policy.get('self_endpoints'), list):
        policy['self_endpoints'] = list(DEFAULT_POLICY['self_endpoints'])
    policy['ignore_own_traffic'] = bool(policy.get('ignore_own_traffic', True))
    return policy


def alertable(hit, min_confidence):
    """A hit raises an alert only when it is protected data of sufficient precision."""
    return bool(hit.get('sensitive', True)) and float(hit.get('confidence', DEFAULT_CONFIDENCE)) >= min_confidence


def host_internal(value, networks):
    """True for addresses that never leave the host: loopback, link-local, unspecified, multicast."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast
            or any(address in network for network in networks))


def excluded_networks(policy):
    networks = []
    for item in policy['exclude_cidrs']:
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    return networks
