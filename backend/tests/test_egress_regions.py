"""The offline CIDR→country table drives the egress verdict; it must be honest."""
from app.services import egress_regions


def test_the_shipped_table_is_present() -> None:
    # A missing table is the degrade path, so the shipped data must actually load.
    assert egress_regions.table_present() is True
    assert (egress_regions.country_table().get("regions") or {}).get("CN")


def test_classification_order_is_whitelist_then_blacklist_then_internal_then_country() -> None:
    kwargs = {"blacklist": [], "whitelist": [], "internal": []}
    assert egress_regions.classify("10.0.0.5", **kwargs)["bucket"] == "internal"
    assert egress_regions.classify("8.8.8.8", **kwargs) == {
        "bucket": "country", "region": "US", "reason": "地区表命中 US"}
    assert egress_regions.classify("8.8.8.8", blacklist=["8.8.8.0/24"], whitelist=[],
                                   internal=[])["bucket"] == "blacklist"
    assert egress_regions.classify("8.8.8.8", blacklist=[], whitelist=["8.8.8.8"],
                                   internal=[])["bucket"] == "whitelist"
    assert egress_regions.classify("203.0.113.9", blacklist=[], whitelist=[],
                                   internal=[])["bucket"] == "internal"


def test_an_unparseable_destination_is_unknown_not_clean() -> None:
    verdict = egress_regions.classify("not-an-ip", blacklist=[], whitelist=[], internal=[])
    assert verdict["bucket"] == "unknown"


def test_policy_normalisation_rejects_a_bad_range() -> None:
    import pytest

    assert egress_regions.normalize_policy({"blacklist": ["10.0.0.0/8"]})["blacklist"] == ["10.0.0.0/8"]
    with pytest.raises(ValueError):
        egress_regions.normalize_policy({"whitelist": ["999.1.1.1"]})
