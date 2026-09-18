"""Where every engine's rules live, and where more of them can be fetched.

The console reports one row per detection engine with the rule files backing it,
so the platform needs a single place that answers two questions:

* which files does this engine actually run (the platform rule library);
* which upstream publishes that engine's rule format, so the library can be
  refreshed online instead of shipping stale rules.

Engines whose detection logic the platform authors itself (protocol, asset,
risk, DLP, threat intel) have no upstream: their rules are maintained here and
``source_url`` stays empty. Every entry names the directories the loader reads,
so a rule file added under them is picked up without a code change.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

RULES_ROOT = Path(__file__).resolve().parent
INTEGRATIONS_ROOT = RULES_ROOT.parent / "integrations"


@dataclass(frozen=True)
class RuleSource:
    """The rule files one engine runs, plus the upstream that publishes them."""

    engine: str
    label: str
    rule_type: str
    directories: tuple[Path, ...]
    patterns: tuple[str, ...] = ("*.yaml", "*.yml")
    # Suricata vendors ship rules in sub-directories (et_open/...), so that
    # entry walks its directory tree instead of only its top level.
    recursive: bool = False
    source_name: str = ""
    source_url: str = ""
    # How the online refresh must interpret the download. Empty means the
    # platform authors these rules and no download exists.
    fetch: str = ""
    # Directory under the runtime integration dir where an online refresh
    # stores the rules it pulled, so a download never rewrites the image.
    runtime_dir: str = ""
    scope: str = ""

    @property
    def refreshable(self) -> bool:
        return bool(self.source_url and self.fetch)


def _rules(name: str) -> Path:
    return RULES_ROOT / name


def _integration(*parts: str) -> Path:
    return INTEGRATIONS_ROOT.joinpath(*parts)


# One entry per engine in the registry. Order matches the console's grouping:
# platform engines first, then the third-party adapters they bridge.
CATALOG: tuple[RuleSource, ...] = (
    RuleSource(
        engine="protocol_engine",
        label="协议分析规则",
        rule_type="protocol",
        directories=(_rules("protocol"),),
        scope="DNS/HTTP/TLS 应用层异常：隧道、隐蔽信道、可疑客户端、动态脚本上传",
    ),
    RuleSource(
        engine="asset_engine",
        label="资产暴露面规则",
        rule_type="asset",
        directories=(_rules("asset"),),
        scope="服务分类、公网暴露与弱认证判定",
    ),
    RuleSource(
        engine="traffic_engine",
        label="流量检测规则",
        rule_type="sigma",
        directories=(_rules("network"),),
        scope="按会话聚合指标判定的网络行为规则",
    ),
    RuleSource(
        engine="data_engine",
        label="数据检测规则",
        rule_type="yara",
        directories=(_rules("data"),),
        patterns=("*.yar", "*.yaml", "*.yml"),
        scope="文件内容 YARA 规则与敏感数据判定参数",
    ),
    RuleSource(
        engine="sigma_log_engine",
        label="日志检测规则",
        rule_type="sigma",
        directories=(_rules("logs"),),
        patterns=("*.yaml", "*.yml"),
        source_name="SigmaHQ",
        source_url="https://github.com/SigmaHQ/sigma",
        fetch="sigma",
        runtime_dir="sigma_rules",
        scope="Sigma 日志规则（本平台解释执行条件字段）",
    ),
    RuleSource(
        engine="compliance_engine",
        label="合规检测规则",
        rule_type="sigma",
        directories=(_rules("compliance"),),
        scope="基线合规项：暴露面、协议合规、补丁与配置要求",
    ),
    RuleSource(
        engine="dlp_engine",
        label="数据外发检测规则",
        rule_type="dlp",
        directories=(_rules("dlp"),),
        scope="被动 DLP 策略：敏感类型、关键字、指纹与置信度阈值",
    ),
    RuleSource(
        engine="threat_intel",
        label="威胁情报规则",
        rule_type="intel",
        directories=(_rules("intel"),),
        source_name="Feodo Tracker / URLhaus",
        source_url="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        scope="IOC 命中与本地 CVE 关联（情报源由 /intelligence/providers 管理）",
    ),
    RuleSource(
        engine="zeek",
        label="Zeek 脚本",
        rule_type="zeek",
        directories=(_integration("zeek", "rules"),),
        patterns=("*.zeek",),
        source_name="Zeek policy scripts",
        source_url="https://github.com/zeek/zeek",
        fetch="zeek",
        runtime_dir="zeek_rules",
        scope="Zeek 站点策略脚本，由 Zeek 在分析时加载",
    ),
    RuleSource(
        engine="suricata",
        label="Suricata 规则",
        rule_type="suricata",
        directories=(_integration("suricata", "rules"),),
        patterns=("*.rules",),
        recursive=True,
        source_name="Emerging Threats Open",
        source_url="https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
        fetch="suricata",
        runtime_dir="suricata_rules",
        scope="Suricata 签名规则（IDS 侧）",
    ),
    RuleSource(
        engine="presidio",
        label="Presidio 识别器",
        rule_type="presidio",
        directories=(_integration("presidio", "rules"),),
        source_name="presidio-analyzer",
        source_url="https://pypi.org/pypi/presidio-analyzer/json",
        fetch="presidio",
        runtime_dir="presidio_rules",
        scope="敏感实体识别器（正则 + 上下文词 + 校验器）",
    ),
    RuleSource(
        engine="misp",
        label="MISP 情报过滤",
        rule_type="misp",
        directories=(_integration("misp", "rules"),),
        source_name="MISP warninglists",
        source_url="https://github.com/MISP/misp-warninglists",
        runtime_dir="misp_rules",
        scope="情报属性过滤：可用于匹配的属性类型与去噪清单",
    ),
    RuleSource(
        engine="osquery",
        label="osquery 查询包",
        rule_type="osquery",
        directories=(_integration("osquery", "rules"),),
        patterns=("*.sql", "*.conf"),
        source_name="osquery packs",
        source_url="https://github.com/osquery/osquery",
        fetch="osquery",
        runtime_dir="osquery_rules",
        scope="主机审计查询（osqueryi --json 执行）",
    ),
    RuleSource(
        engine="wazuh",
        label="Wazuh 检测规则",
        rule_type="wazuh",
        directories=(_integration("wazuh", "rules"),),
        patterns=("*.xml",),
        source_name="Wazuh ruleset",
        source_url="https://github.com/wazuh/wazuh/tree/master/ruleset",
        fetch="wazuh",
        runtime_dir="wazuh_rules",
        scope="Wazuh 解码与告警规则（local_rules.xml 语义）",
    ),
    RuleSource(
        engine="openscap",
        label="OpenSCAP 基线",
        rule_type="openscap",
        directories=(_integration("openscap", "rules"),),
        patterns=("*.xml",),
        source_name="ComplianceAsCode content",
        source_url="https://github.com/ComplianceAsCode/content",
        fetch="openscap",
        runtime_dir="openscap_rules",
        scope="XCCDF 基线检查项（oscap xccdf eval 执行）",
    ),
)


def by_engine() -> dict[str, RuleSource]:
    return {item.engine: item for item in CATALOG}


def for_engine(engine: str) -> RuleSource | None:
    return by_engine().get(engine)


def engine_of_directory(path: Path) -> str:
    """Map a rule file back to its engine, used when listing the library."""
    resolved = Path(path)
    for item in CATALOG:
        for directory in item.directories:
            try:
                resolved.relative_to(directory)
            except ValueError:
                continue
            return item.engine
    return ""


def iter_directories() -> list[Path]:
    return [directory for item in CATALOG for directory in item.directories]
