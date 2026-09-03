# Data Security Toolbox Manual Test Pack

This package is intentionally harmless and designed only for your isolated/private test environment.

Recommended order:
1. Import `threat_intel/iocs.csv`, `threat_intel/local_cve.json`,
   `rules/dst_e2e_suricata.rules`, and `rules/dst_e2e_sigma.yml`.
2. Upload the sensitive-data and file-analysis samples.
3. Paste/upload `logs/abnormal_security.log`.
4. Test osquery/Wazuh/OpenSCAP integration pages with their JSON samples.
5. Upload each PCAP and inspect Task -> Finding -> Risk -> Incident -> Alert -> PCAP evidence.
6. For `http_suspicious_ua.pcap`, verify both protocol/Zeek extraction and the imported Suricata SID 990001 rule if your worker loads active offline rules.
7. Verify sensitive values are masked in the UI.

Important:
- No real malware is included.
- No real credentials are included.
- No public IP is targeted.
- `.test` domains and RFC1918 private IPs are used.
