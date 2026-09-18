"""Definitions for the detection rules the platform implements in code.

An alert has to be able to show the rule that matched, not only its id. Rules
authored as files live in the rule library and are read from disk; the rules
below are applied by engine code instead, so their definition is declared here
next to the engine that runs them. Every entry mirrors the id, severity and
threshold the engine actually enforces -- nothing here describes a rule the
engines do not run.
"""

from typing import Any

# ``source`` names the module that implements the rule, so the console can point
# an operator at the code instead of an empty "rule file" cell.
BUILTIN_RULES: dict[str, dict[str, Any]] = {
    "PROTO_DNS_TUNNEL_001": {
        "engine": "protocol_engine",
        "title": "DNS 隧道 / 异常编码域名",
        "severity": "High",
        "condition": "entropy(dns.qry.name) >= 3.5 或 len(dns.qry.name) >= 40",
        "recommendation": "排查是否存在 DNS 隧道、DGA 域名或异常编码域名。",
        "source": "app/engine/protocol_engine/engine.py",
    },
    "PROTO_DNS_TXT_001": {
        "engine": "protocol_engine",
        "title": "大 TXT 记录（疑似隐蔽信道）",
        "severity": "Medium",
        "condition": "len(dns.txt) > 200",
        "recommendation": "检查大 TXT 记录是否用于数据外传或隐蔽通信。",
        "source": "app/engine/protocol_engine/engine.py",
    },
    "PROTO_HTTP_UA_001": {
        "engine": "protocol_engine",
        "title": "可疑 User-Agent（扫描/自动化工具）",
        "severity": "Medium",
        "condition": "http.user_agent ~ (sqlmap|nikto|nmap|python-requests|curl/|wget/)",
        "recommendation": "识别异常 User-Agent 来源，结合请求序列判断是否为扫描或自动化攻击。",
        "source": "app/engine/protocol_engine/engine.py",
    },
    "PROTO_HTTP_UPLOAD_001": {
        "engine": "protocol_engine",
        "title": "动态脚本上传（疑似 WebShell）",
        "severity": "High",
        "condition": "http.request.method in {POST,PUT,PATCH} 且 uri 含 .php/.jsp/.asp",
        "recommendation": "对动态脚本上传请求进行审计，结合文件内容判断是否存在 WebShell 上传。",
        "source": "app/engine/protocol_engine/engine.py",
    },
    "NETWORK_PORT_SCAN": {
        "engine": "traffic_engine",
        "title": "端口扫描",
        "severity": "High",
        "condition": "同一源地址在滚动窗口内访问的不同目标端口数 >= port_scan_ports_threshold",
        "recommendation": "结合会话证据排查异常行为来源和目标。",
        "source": "app/engine/traffic_engine/engine.py",
    },
    "NET_C2_BEACON_001": {
        "engine": "traffic_engine",
        "title": "C2 周期性心跳",
        "severity": "High",
        "condition": "同一五元组会话报文数 >= 10 且 心跳间隔标准差/均值 < 0.2",
        "recommendation": "排查是否存在 C2 周期性心跳，结合 DNS/HTTP/证书证据确认外联行为。",
        "source": "app/engine/traffic_engine/engine.py",
    },
    "broad_communication": {
        "engine": "traffic_engine",
        "title": "大流量多目标通信",
        "severity": "Medium",
        "condition": "同一源地址目标数 >= 10 且 流量 > 10 MB",
        "recommendation": "结合会话证据排查异常行为来源和目标。",
        "source": "app/engine/traffic_engine/engine.py",
    },
    "high_packet_rate": {
        "engine": "traffic_engine",
        "title": "报文速率异常",
        "severity": "Medium",
        "condition": "报文速率 > 500 pps",
        "recommendation": "结合会话证据排查异常行为来源和目标。",
        "source": "app/engine/traffic_engine/engine.py",
    },
    "COMP_WEAK_PROTOCOL_001": {
        "engine": "compliance_engine",
        "title": "明文/弱认证协议",
        "severity": "High",
        "condition": "资产服务 in {telnet, ftp, smtp}",
        "recommendation": "禁用明文/弱认证协议，改用 SSH、SFTP、TLS 等加密协议。",
        "source": "app/engine/compliance_engine/engine.py",
    },
    "DATA_PII_001": {
        "engine": "data_engine",
        "title": "文件/文本包含个人信息（PII）",
        "severity": "High",
        "condition": "PII 命中数 > 0（身份证、手机号、银行卡、邮箱等）",
        "recommendation": "对包含身份证、手机号、银行卡、邮箱等 PII 的文件实施加密、脱敏和访问控制。",
        "source": "app/engine/data_engine/engine.py",
    },
    "DATA_SECRET_001": {
        "engine": "data_engine",
        "title": "文件/文本包含密钥或凭据",
        "severity": "Critical",
        "condition": "密钥/Token 命中数 > 0 或存在高熵凭据",
        "recommendation": "立即轮换泄露的密钥/Token，并排查代码、配置和备份文件。",
        "source": "app/engine/data_engine/engine.py",
    },
    "DATA_YARA_001": {
        "engine": "data_engine",
        "title": "文件命中 YARA 规则",
        "severity": "High",
        "condition": "文件内容命中 data 目录 YARA 规则集",
        "recommendation": "根据 YARA 规则检查文件来源、作者和是否包含恶意/敏感内容。",
        "source": "app/engine/data_engine/engine.py",
    },
    "ASSET_PUBLIC_DB_001": {
        "engine": "asset_engine",
        "title": "数据库服务暴露在公网",
        "severity": "Critical",
        "condition": "服务类别 in {redis,mysql,postgresql,mongodb,oracle} 且 public_exposed = true",
        "recommendation": "数据库服务不得暴露在公网，应限制来源网段并启用加密认证。",
        "source": "app/engine/asset_engine/engine.py",
    },
    "ASSET_DB_WEAK_AUTH_001": {
        "engine": "asset_engine",
        "title": "数据库服务弱认证",
        "severity": "High",
        "condition": "服务类别 in {redis,mysql,postgresql,mongodb,oracle} 且 weak_auth = true（空密码/匿名/无认证标识）",
        "recommendation": "启用强认证、最小权限和访问审计，禁止空密码或匿名认证。",
        "source": "app/engine/asset_engine/engine.py",
    },
    "ASSET_PUBLIC_WEB_001": {
        "engine": "asset_engine",
        "title": "Web 服务暴露在公网",
        "severity": "Medium",
        "condition": "服务类别 in {web,nginx,apache,iis,tomcat} 且 public_exposed = true",
        "recommendation": "公网 Web 服务应启用 TLS、WAF、补丁管理和访问日志。",
        "source": "app/engine/asset_engine/engine.py",
    },
    "TI_IOC_001": {
        "engine": "threat_intel",
        "title": "通信命中威胁情报 IOC",
        "severity": "High",
        "condition": "观测到的 IP/域名/URL 命中威胁情报库 IOC",
        "recommendation": "对命中 IOC 的通信进行阻断、隔离和取证。",
        "source": "app/threat_intel/engine.py",
    },
}


def builtin_rule_definition(rule_id: str) -> dict[str, Any] | None:
    """Return the declared definition of a code-implemented rule, if it has one."""
    entry = BUILTIN_RULES.get(rule_id)
    if not entry:
        return None
    return {
        "rule_id": rule_id,
        "type": "builtin",
        "path": str(entry["source"]),
        "file": str(entry["source"]),
        "content": "",
        "detection": None,
        **entry,
    }


def dlp_rule_definition(rule_id: str, policy: dict[str, Any] | None) -> dict[str, Any] | None:
    """Describe the DLP rule from the live policy the engine actually applied.

    The DLP engine has no rule file: what it enforces is the stored policy, so
    the definition is rendered from that policy instead of being hard-coded.
    """
    if rule_id != "DLP_TRANSFER_001":
        return None
    policy = policy or {}
    categories = [str(item) for item in policy.get("categories") or []]
    keywords = [str(item) for item in policy.get("keywords") or []]
    fingerprints = [str(item) for item in policy.get("fingerprints") or []]
    pieces = []
    if categories:
        pieces.append("敏感类型 " + "/".join(categories))
    if keywords:
        pieces.append(f"关键词 {len(keywords)} 个")
    if fingerprints:
        pieces.append(f"文件指纹 {len(fingerprints)} 个")
    matched = "、".join(pieces) if pieces else "内置敏感数据识别"
    condition = (
        f"HTTP 会话体命中 {matched}，"
        f"命中数 >= {policy.get('min_matches', 1)} 且置信度 >= {policy.get('min_confidence', 0)}"
    )
    return {
        "rule_id": rule_id,
        "engine": "dlp_engine",
        "type": "policy",
        "path": "system_setting: dlp_policy",
        "file": "DLP 检测策略（system_setting: dlp_policy）",
        "content": "",
        "title": "敏感数据外发（被动 DLP）",
        "severity": "High",
        "condition": condition,
        "recommendation": "核查传输目的地和业务授权；对敏感内容脱敏、加密，必要时通过网关或终端策略阻断。",
        "detection": {
            "categories": categories,
            "keywords": keywords,
            "fingerprints": fingerprints,
            "min_matches": policy.get("min_matches", 1),
            "min_confidence": policy.get("min_confidence", 0),
            "exclude_cidrs": list(policy.get("exclude_cidrs") or []),
            "mode": "passive",
        },
    }


def cve_rule_definition(rule_id: str, evidence: dict[str, Any] | None = None, record: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Describe a CVE hit from the vulnerability record the engine matched.

    ``record`` is the matching row of the platform's local CVE library when one
    exists; the finding's own evidence is the fallback for CVEs that were
    resolved online and never imported.
    """
    if not rule_id.startswith("CVE_"):
        return None
    evidence = evidence if isinstance(evidence, dict) else {}
    record = record if isinstance(record, dict) else {}
    cve = evidence.get("cve") if isinstance(evidence.get("cve"), dict) else {}
    cve_id = str(record.get("cve_id") or cve.get("cve_id") or rule_id.removeprefix("CVE_"))
    asset = evidence.get("asset") if isinstance(evidence.get("asset"), dict) else {}
    keyword = " ".join(str(asset.get(key) or "") for key in ("service", "version")).strip()
    # The asset inventory stores "unknown" for ports it could not fingerprint, and
    # the engine looks that literal value up like any other keyword. Echoing it
    # back as the rule name ("CVE-1999-1573 影响 unknown") tells an operator
    # nothing, so placeholder values fall back to the generic wording.
    named = keyword.lower() not in {"", "unknown", "none", "n/a", "n.a.", "-"}
    description = record.get("description") or cve.get("description") or ""
    if isinstance(description, dict):
        description = description.get("text") or ""
    score = record.get("cvss_score") or 0
    condition = f"资产服务关键字 '{keyword}' 命中本地漏洞库记录 {cve_id}" if named else f"资产服务关键字命中本地漏洞库记录 {cve_id}"
    if score:
        condition += f"（CVSS {score:g}）"
    if named:
        title = f"{cve_id} 影响 {keyword}"
    elif asset.get("port"):
        title = f"{cve_id} 影响资产服务（端口 {asset.get('port')}）"
    else:
        title = f"{cve_id} 影响资产服务"
    return {
        "rule_id": rule_id,
        "engine": "threat_intel",
        "type": "cve",
        "path": "local_cves" if record else "nvd:cve_lookup",
        "file": "本地漏洞库（local_cves，按资产服务/版本查表）" if record else "NVD 漏洞库（按资产服务/版本查表）",
        "content": "",
        "title": title,
        "severity": str(record.get("severity") or "High"),
        "condition": condition,
        "recommendation": f"根据 {cve_id} 评估并修复受影响资产。",
        "description": str(description),
        "detection": {
            "cve_id": cve_id,
            "severity": str(record.get("severity") or ""),
            "cvss_score": score,
            "published": str(record.get("published") or cve.get("published") or ""),
            "asset": asset,
        },
    }
