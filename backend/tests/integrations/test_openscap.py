from pathlib import Path

from app.integrations.openscap.adapter import OpenSCAPAdapter
from app.integrations.openscap.parser import parse_xccdf_xml

XCCDF = '''<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="xccdf_org.cis.benchmark">
  <title>CIS Benchmark</title>
  <Profile id="xccdf_org.cis.profile"><title>Level 1</title></Profile>
  <TestResult>
    <rule-result idref="xccdf_org.cis.rule_1" result="fail"><result>fail</result><title>Ensure password max age</title><ident>CVE-2026-0001</ident></rule-result>
  </TestResult>
</Benchmark>'''


def test_openscap_fail_result() -> None:
    result = OpenSCAPAdapter().adapt({"results": [{"idref": "xccdf_org.cis.rule_1", "result": "fail", "title": "Ensure password max age", "profile": "Level 1"}]})
    assert any(item.rule_id == "OPENSCAP_xccdf_org.cis.rule_1" for item in result.findings)


def test_openscap_xml_parser(tmp_path: Path) -> None:
    path = tmp_path / "results.xml"
    path.write_text(XCCDF, encoding="utf-8")
    records = parse_xccdf_xml(path)
    assert records
    assert records[0]["result"] == "fail"


def test_openscap_payload() -> None:
    result = OpenSCAPAdapter().adapt({"results": [{"idref": "rule-2", "result": "error", "title": "SSH root login", "profile": "DengBao"}]})
    assert any(item.rule_id == "OPENSCAP_rule-2" for item in result.findings)
