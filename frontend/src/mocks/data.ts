// ============================================================
// Demo mock data — realistic SOC/NDR/data-security sample data.
// ONLY used when VITE_DEMO_MODE=true (port 5174). Never used by 5173.
// ============================================================

const now = Date.now()
export const iso = (ms: number) => new Date(ms).toISOString()
const ago = (min: number) => iso(now - min * 60_000)

export const health = {
  status: 'ok', service: 'Data Security Toolbox', api: 'ok', database: 'ok', redis: 'ok',
  celery: { broker: 'ok', workers: 3, running: 2, queued: 4 },
  analysis_worker: 'ready',
  tshark: { available: true, version: '4.2.5' },
  zeek: { available: true, version: '5.2.0' },
  suricata: { available: true, version: '7.0.4', rule_count: 2417 },
  storage_usage_bytes: 42_000_000_000,
  storage_max_bytes: 100 * 1024 * 1024 * 1024,
  queue: { pending: 4, running: 2, oldest_pending_age: 12 },
  probe: { count: 12, online: 9, degraded: 1, offline: 2, auth_error: 0 },
}

export const dashboardSummary = {
  assets: 128, files: 342, pcaps: 56, anomalies: 87, tasks: 1420, reports: 18,
  probes: 12, incidents: 23, iocs: 156, alerts: 482, open_alerts: 37,
  high_risk_findings: 64, open_incidents: 11, high_risk_assets: 19,
  sensitive_data_assets: 42, online_probes: 9, healthy_integrations: 5,
}

export const riskSummary = {
  count: 1284,
  risk_levels: { Critical: 18, High: 64, Medium: 312, Low: 890 },
  engines: { traffic: 420, protocol: 180, zeek: 210, suricata: 150, data: 96, sigma: 88, ioc: 64, compliance: 76 },
  asset_risk: { Critical: 6, High: 19, Medium: 58, Low: 45 },
  data_sensitivity: { Critical: 11, High: 42, Medium: 130, Low: 96 },
  max_score: 98, avg_score: 41.6,
}

const trendDays = ['09-02', '09-03', '09-04', '09-05', '09-06', '09-07', '09-08']
export const riskTrend = {
  range: '7d',
  items: trendDays.map((time, i) => ({
    time, risk_score: 60 + i * 5 + (i % 3) * 4, count: 80 + i * 18, critical: i % 2, high: 8 + i * 3,
  })),
}

export const dashboardSeverity = { items: [
  { severity: 'Critical', count: 18 }, { severity: 'High', count: 64 },
  { severity: 'Medium', count: 312 }, { severity: 'Low', count: 890 },
] }

export const dashboardEngines = { items: [
  { engine: 'traffic', count: 420 }, { engine: 'protocol', count: 180 }, { engine: 'zeek', count: 210 },
  { engine: 'suricata', count: 150 }, { engine: 'data', count: 96 }, { engine: 'sigma', count: 88 },
  { engine: 'ioc', count: 64 }, { engine: 'compliance', count: 76 },
] }

export const dashboardSensitive = { items: [
  { category: '身份证', count: 96 }, { category: '手机号', count: 142 }, { category: '银行卡', count: 38 },
  { category: 'Email', count: 210 }, { category: '医疗数据', count: 24 }, { category: 'Secret', count: 12 },
] }

// ---------------- Alerts ----------------
export const alerts = Array.from({ length: 22 }, (_, i) => {
  const sev = ['Critical', 'High', 'Medium', 'Low'][i % 4]
  const engines = ['traffic', 'protocol', 'zeek', 'suricata', 'data', 'sigma', 'ioc', 'compliance']
  const titles = [
    '检测到端口扫描行为', '可疑 DNS 隧道外联', 'HTTP 异常 User-Agent', 'IOC 命中恶意 IP',
    '敏感数据外发检测', 'TLS 证书异常指纹', 'SQL 注入尝试', '暴力破解登录失败',
    '文件上传 webshell 检测', 'C2 通信 Beacon 检测', '异常流量突增', '合规基线违规',
  ]
  return {
    id: 5000 + i, fingerprint: `fp_${(0x1a2b3c4d + i * 0x1f).toString(16)}`,
    finding_id: 900 + i, incident_id: i % 3 === 0 ? 700 + Math.floor(i / 3) : null,
    probe_id: 1 + (i % 6), severity: sev, risk_score: 98 - i * 3,
    title: titles[i % titles.length], summary: `来自 ${'10.0.' + (i % 5) + '.' + (i * 7 % 250)} 的${titles[i % titles.length]}`,
    status: ['new', 'acknowledged', 'resolved', 'suppressed'][i % 4],
    first_seen: ago(300 + i * 40), last_seen: ago(10 + i * 5), occurrence_count: 1 + (i % 9),
    source: engines[i % engines.length], created_at: ago(300 + i * 40), updated_at: ago(10 + i * 5),
  }
})

export const alertSummary = {
  total: 482, status: { new: 37, acknowledged: 121, resolved: 296, suppressed: 28 },
  severity: { Critical: 18, High: 64, Medium: 312, Low: 88 }, unhandled_critical_high: 12,
}

// ---------------- Incidents ----------------
export const incidents = Array.from({ length: 12 }, (_, i) => {
  const stages = ['recon', 'exploit', 'c2', 'exfil']
  return {
    id: 700 + i, fingerprint: `inc_fp_${i}`, probe_id: 1 + (i % 6), source: 'incident_engine',
    title: `攻击链：资产 10.0.${i % 4}.${20 + i} -> ${stages.join(' -> ')}`,
    severity: ['Critical', 'High', 'Medium'][i % 3], confidence: 0.78 + (i % 4) * 0.05,
    status: ['open', 'investigating', 'contained', 'resolved'][i % 4],
    findings: { items: Array.from({ length: 3 + (i % 3) }, (_, j) => ({ id: 900 + i * 10 + j, engine: 'traffic', rule_id: `RULE-${100 + i * 10 + j}`, severity: 'High', risk_score: 80 - j, timestamp: ago(100 - j * 10), confidence: 0.7, evidence: { ip: `10.0.${i % 4}.${20 + i}` } })) },
    evidence: { stages, asset: `10.0.${i % 4}.${20 + i}`, ioc: i % 2 ? `evil${i}.c2domain.com` : undefined },
    risk_score: 92 - i * 4, risk_level: ['Critical', 'High', 'Medium'][i % 3],
    timestamp: ago(200 - i * 12), last_seen: ago(15 + i * 4), occurrence_count: 1 + (i % 5),
    created_at: ago(200 - i * 12), updated_at: ago(15 + i * 4),
  }
})

// ---------------- Detections ----------------
export const detections = Array.from({ length: 16 }, (_, i) => ({
  id: 900 + i, task_id: 100 + i, target_type: ['pcap', 'asset', 'file', 'integration'][i % 4],
  target_id: String(1 + (i % 8)), engine: ['traffic', 'protocol', 'zeek', 'suricata', 'data', 'sigma', 'ioc', 'compliance'][i % 8],
  rule_id: `RULE-${100 + i * 7}`, severity: ['Critical', 'High', 'Medium', 'Low'][i % 4],
  confidence: 0.7 + (i % 5) * 0.06, evidence: { ip: `10.0.${i % 4}.${20 + i}`, protocol: 'TCP', port: [80, 443, 53, 8080][i % 4], value: i % 3 ? `evil${i}.domain.com` : '185.220.101.' + i },
  recommendation: '建议阻断异常来源并隔离受影响资产', risk_score: 95 - i * 3,
  risk_level: ['Critical', 'High', 'Medium', 'Low'][i % 4], timestamp: ago(400 - i * 20), created_at: ago(400 - i * 20),
}))

// ---------------- Assets ----------------
export const assets = Array.from({ length: 14 }, (_, i) => ({
  id: 300 + i, probe_id: 1 + (i % 6), ip: `10.0.${i % 4}.${20 + i}`,
  hostname: `srv-${String(i + 1).padStart(2, '0')}.internal`, os: ['Ubuntu 22.04', 'Windows Server 2019', 'CentOS 7', 'Debian 12'][i % 4],
  port: [80, 443, 3306, 22, 8080][i % 5], protocol: ['tcp', 'tcp', 'tcp', 'tcp', 'tcp'][i % 5],
  service: ['nginx', 'apache', 'mysql', 'ssh', 'tomcat'][i % 5],
  asset_type: ['server', 'database', 'workstation', 'network'][i % 4],
  risk_level: ['Critical', 'High', 'Medium', 'Low'][i % 4],
  sensitive_categories: i % 2 ? ['phone', 'id_card'] : [],
  metadata: {}, first_seen: ago(3000 - i * 100), last_seen: ago(20 + i * 3),
}))

// ---------------- PCAPs ----------------
export const pcaps = Array.from({ length: 8 }, (_, i) => ({
  id: 100 + i, probe_id: 1 + (i % 6), segment_id: `seg-${100 + i}`, sequence: i,
  capture_interface: 'eth0', capture_started_at: ago(600 - i * 60), capture_finished_at: ago(560 - i * 60),
  ingest_status: 'ingested', analysis_status: 'analyzed', probe_metadata: {},
  filename: `capture_2026-09-0${1 + (i % 8)}_${(i * 13) % 60}.pcap`, size: 2_400_000 + i * 1_800_000,
  sha256: 'a1b2c3d4' + 'e5f6'.repeat(4) + i.toString(16).padStart(4, '0'),
  packet_count: 12_000 + i * 8_000, total_packet_count: 12_000 + i * 8_000, indexed_packet_count: 12_000 + i * 8_000,
  duration: 60 + i * 30, capture_start: ago(600 - i * 60), capture_end: ago(560 - i * 60),
  file_type: 'pcap', protocol_summary: { TCP: 4200 + i * 300, UDP: 1800 + i * 200, DNS: 800 + i * 100, HTTP: 1500 + i * 120, TLS: 900 + i * 90 },
  status: ['analyzed', 'analyzed', 'retained_analysis', 'pending', 'analyzed', 'analyzed', 'failed', 'analyzed'][i],
  retention_status: 'active', created_at: ago(600 - i * 60),
}))

export const flows = Array.from({ length: 24 }, (_, i) => ({
  id: 1 + i, src_ip: `10.0.${i % 3}.${10 + i}`, src_port: 50000 + i,
  dst_ip: ['185.220.101.' + (i % 250), '8.8.8.8', '142.250.72.14', '10.0.1.5'][i % 4],
  dst_port: [80, 443, 53, 8080][i % 4], protocol: ['TCP', 'UDP'][i % 2],
  app_protocol: ['HTTP', 'TLS', 'DNS', 'HTTP'][i % 4], packets: 10 + i * 7, bytes: 1200 + i * 900,
  start_time: ago(60 + i), end_time: ago(58 + i),
}))

export const packets = Array.from({ length: 48 }, (_, i) => ({
  id: 1 + i, number: i + 1, timestamp: now - i * 1000,
  src_ip: i % 2 ? `10.0.1.${20 + i}` : '185.220.101.77',
  dst_ip: i % 2 ? '185.220.101.77' : `10.0.1.${20 + i}`,
  src_port: i % 2 ? 50000 + i : 443, dst_port: i % 2 ? 443 : 50000 + i,
  protocol: ['TCP', 'TCP', 'UDP', 'TCP'][i % 4], length: 54 + (i % 5) * 120,
  info: ['[SYN] Seq=0 Win=64240', '[ACK] Seq=1 Ack=1 Win=64240', 'DNS Query A evil' + i + '.domain.com', 'TLSv1.3 Handshake'][i % 4],
}))

export const pcapAlerts = { items: [
  { kind: 'anomaly', severity: 'High', title: '端口扫描异常', description: '检测到同一源对多端口的高频 SYN', source: 'builtin', evidence: { src_ip: '185.220.101.77' } },
  { kind: 'finding', severity: 'Critical', title: 'RULE-107', description: 'IOC 命中恶意 IP', source: 'ioc', evidence: { value: '185.220.101.77' } },
  { kind: 'external', severity: 'High', title: 'Suricata: ET SCAN Nmap', description: 'ET SCAN Nmap Script', source: 'suricata', evidence: { signature: 'ET SCAN Nmap' } },
] }

export const pcapDns = { items: Array.from({ length: 8 }, (_, i) => ({ query: `evil${i}.domain.com`, type: 'A', rcode: 'NOERROR', source: 'zeek', qname: `evil${i}.domain.com`, name: `evil${i}.domain.com` })) }
export const pcapHttp = { items: Array.from({ length: 8 }, (_, i) => ({ method: ['GET', 'POST'][i % 2], uri: `/api/v1/secret/${i}`, host: `api.internal:${8000 + i}`, status: [200, 200, 403, 500][i % 4], user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', source: 'zeek' })) }
export const pcapTls = { items: Array.from({ length: 6 }, (_, i) => ({ server_name: `cdn${i}.example.com`, sni: `cdn${i}.example.com`, cipher: 'TLS_AES_128_GCM_SHA256', ja3: 'a0e9f5d64349fb13191bc72b', version: 'TLSv1.3', source: 'zeek' })) }
export const pcapFiles = { items: Array.from({ length: 5 }, (_, i) => ({ filename: `file_${i}.bin`, name: `file_${i}.bin`, mime_type: 'application/octet-stream', magic: 'PDF', size: 12000 + i * 5000, sha256: 'c0ffee' + i.toString(16).padStart(4, '0'), source: 'zeek' })) }
export const pcapProtocols = [ { name: 'TCP', count: 4200 }, { name: 'UDP', count: 1800 }, { name: 'DNS', count: 800 }, { name: 'HTTP', count: 1500 }, { name: 'TLS', count: 900 } ]
export const pcapAnomalies = [ { id: 1, rule: '端口扫描', severity: 'High', description: '高频 SYN 扫描', evidence: {} }, { id: 2, rule: 'DNS 高熵', severity: 'Medium', description: '异常高熵域名', evidence: {} } ]
export const traffic = {
  trend: Array.from({ length: 12 }, (_, i) => ({ time: `09-0${1 + Math.floor(i / 4)} ${String(8 + i % 4).padStart(2, '0')}:00`, packets: 300 + i * 40, bytes: 50000 + i * 8000 })),
  top_n: flows.slice(0, 5),
  protocols: { TCP: 4200, UDP: 1800, DNS: 800, HTTP: 1500, TLS: 900 },
  hosts: Array.from({ length: 6 }, (_, i) => ({ ip: `10.0.${i % 3}.${10 + i}`, bytes: 20000 + i * 7000, packets: 400 + i * 50 })),
  anomalies: pcapAnomalies,
}

// ---------------- Data Assets ----------------
export const dataAssets = Array.from({ length: 10 }, (_, i) => ({
  id: 400 + i, name: ['customers', 'orders', 'employees', 'payments', 'medical_records', 'user_profiles', 'logs', 'tickets', 'invoices', 'devices'][i],
  asset_type: ['database', 'file', 'api'][i % 3], sensitivity: ['Critical', 'High', 'Medium', 'Low'][i % 4],
  source: ['postgres://customers', 's3://backup', '/data/orders.csv', 'api://payments'][i % 4],
  columns: [
    { name: 'id', sensitivity: 'Low', detected_type: 'number', confidence: 0.99, count: 10000 },
    { name: ['phone', 'id_card', 'email', 'bank_card', 'name'][i % 5], sensitivity: 'High', detected_type: 'PII', confidence: 0.95, count: 9800, categories: [['phone'], ['id_card'], ['email'], ['bank_card'], ['name']][i % 5] },
    { name: 'created_at', sensitivity: 'Low', detected_type: 'date', confidence: 0.9, count: 10000 },
  ],
  extra: {}, created_at: ago(5000 - i * 200),
}))

export const files = Array.from({ length: 8 }, (_, i) => ({
  id: 200 + i, probe_id: 1 + (i % 4), name: ['report_final.pdf', 'invoice_2026.docx', 'photo_001.jpg', 'config.yaml', 'db_dump.sql', 'README.txt', 'malware_like.bin', 'sensitive_data.xlsx'][i],
  path: `/data/uploads/${['report_final.pdf', 'invoice_2026.docx', 'photo_001.jpg', 'config.yaml', 'db_dump.sql', 'README.txt', 'malware_like.bin', 'sensitive_data.xlsx'][i]}`,
  size: 200_000 + i * 150_000, sha256: 'd4c3b2a1' + i.toString(16).padStart(4, '0') + 'e'.repeat(8),
  file_type: ['pdf', 'docx', 'jpg', 'yaml', 'sql', 'txt', 'bin', 'xlsx'][i],
  metadata_json: { exif: i === 2 ? { Make: 'Canon', Model: 'EOS 5D' } : {}, pdf: i === 0 ? { Author: 'Admin', Pages: 12 } : {}, docx: i === 1 ? { Creator: 'MS Word', Company: 'Acme' } : {}, yara: i === 6 ? { rule: 'eicar', matched: true } : {}, hidden_data: i === 6 ? ['embedded_payload'] : [] },
  risk_level: ['Medium', 'Low', 'Low', 'Medium', 'High', 'Low', 'Critical', 'High'][i], created_at: ago(2000 - i * 100),
}))

// ---------------- IOCs ----------------
export const iocs = Array.from({ length: 12 }, (_, i) => ({
  id: 600 + i, type: ['ip', 'domain', 'url', 'hash'][i % 4],
  value: ['185.220.101.' + (i % 250), `evil${i}.c2domain.com`, `http://evil${i}.com/payload`, 'e3b0c44298fc1c149afbf4c8996fb924'][i % 4],
  source: ['misp', 'offline', 'manual'][i % 3], first_seen: ago(2000 - i * 50), last_seen: ago(100 + i * 20),
  tags: ['malware', 'c2', 'phishing'][i % 3].split(','), metadata: {}, created_at: ago(2000 - i * 50),
}))

export const localCves = Array.from({ length: 10 }, (_, i) => ({
  cve_id: `CVE-2026-${1000 + i * 37}`, source: 'offline',
  severity: ['Critical', 'High', 'Medium'][i % 3], cvss_score: [9.8, 8.1, 5.4][i % 3],
  published: ago(3000 - i * 200), modified: ago(1000 - i * 100),
  description: { en: `Remote code execution in ${['nginx', 'openssl', 'log4j', 'tomcat'][i % 4]}`, zh: `在 ${['nginx', 'openssl', 'log4j', 'tomcat'][i % 4]} 中的远程代码执行漏洞` },
}))

export const offlineResources = Array.from({ length: 6 }, (_, i) => ({
  id: 800 + i, resource_type: ['ioc', 'cve', 'suricata_rules', 'sigma_rules', 'model'][i % 5],
  name: ['offline_iocs_v2', 'cve_2026_local', 'suricata_ruleset_2026', 'sigma_rules_enterprise', 'pii_model_v3', 'ioc_blacklist'][i],
  version: '2.0.' + i, count: [1560, 3200, 2417, 88, 1, 890][i], status: ['imported', 'imported', 'imported', 'imported', 'imported', 'imported'][i],
  storage_path: `/data/integrations/${i}`, manifest_path: `/data/integrations/${i}/MANIFEST.json`,
  resource_metadata: { source: 'offline', rule_count: [1560, 3200, 2417, 88, 1, 890][i] }, imported_at: ago(5000 - i * 300),
}))

// ---------------- Integrations ----------------
export const integrations = [
  { name: 'zeek', adapter_version: '1.0.0', version: '5.2.0', runtime_version: '5.2.0', installed: true, enabled: true, healthy: true, supported_types: ['pcap', 'traffic'], capabilities: ['dns', 'http', 'ssl', 'files'], last_check: ago(5), status: 'ready', message: '' },
  { name: 'suricata', adapter_version: '1.0.0', version: '7.0.4', runtime_version: '7.0.4', installed: true, enabled: true, healthy: true, supported_types: ['pcap', 'traffic'], capabilities: ['ids', 'alert', 'fileinfo'], last_check: ago(6), status: 'ready', message: '' },
  { name: 'presidio', adapter_version: '1.0.0', version: '2.2', runtime_version: '2.2', installed: true, enabled: true, healthy: true, supported_types: ['data'], capabilities: ['pii', 'sensitive'], last_check: ago(7), status: 'ready', message: '' },
  { name: 'misp', adapter_version: '1.0.0', version: '2.4', runtime_version: '', installed: true, enabled: true, healthy: true, supported_types: ['ioc'], capabilities: ['ioc', 'threat'], last_check: ago(9), status: 'ready', message: '' },
  { name: 'osquery', adapter_version: '1.0.0', version: '5.12', runtime_version: '', installed: true, enabled: true, healthy: true, supported_types: ['host'], capabilities: ['audit'], last_check: ago(8), status: 'ready', message: '' },
  { name: 'wazuh', adapter_version: '1.0.0', version: '4.9', runtime_version: '', installed: true, enabled: true, healthy: true, supported_types: ['host'], capabilities: ['siem'], last_check: ago(11), status: 'ready', message: '' },
  { name: 'openscap', adapter_version: '1.0.0', version: '1.3', runtime_version: '', installed: true, enabled: true, healthy: true, supported_types: ['compliance'], capabilities: ['scan'], last_check: ago(12), status: 'ready', message: '' },
]

export const engineRegistry = [
  { name: 'traffic', version: '1.0.0', description: '流量检测引擎' },
  { name: 'protocol', version: '1.0.0', description: '协议分析引擎' },
  { name: 'data', version: '1.0.0', description: '数据安全引擎' },
  { name: 'risk', version: '1.0.0', description: '风险引擎' },
]

// ---------------- Probes ----------------
export const probes = Array.from({ length: 6 }, (_, i) => ({
  id: 1 + i, name: `probe-edge-${i + 1}`, hostname: `edge-${i + 1}.internal`, ip_address: `10.0.0.${10 + i}`,
  status: ['online', 'online', 'online', 'degraded', 'online', 'offline'][i], last_seen: ago(5 + i * 2),
  metadata: {
    cpu_percent: 22 + i * 7, memory_percent: 48 + i * 5, capture_status: 'online', interface: 'eth0',
    // Rule version reporting: one probe is deliberately behind and one carries a
    // failed hot-update reason so the demo shows the real states, not a happy path.
    current_ruleset_version: i === 5 ? '' : i === 3 ? 'builtin-1.0.0' : 'builtin-1',
    ruleset_source: i === 3 || i === 5 ? 'builtin' : 'server',
    engine_version: '1.0.0',
    capabilities: { ruleset_hot_update: i !== 5, sensitive_detection_v2: true, regex_timeout: true },
    ruleset_last_error: i === 3 ? 'SHA256 不匹配: 期望 630eb7dfe508 实际 0011223344ff' : '',
  },
  created_at: ago(5000),
}))

export const ruleSets = {
  items: [{
    id: 1, name: 'default', description: '内置与人工维护的检测规则',
    active_version: {
      id: 2, version: 'builtin-1', status: 'published', rule_count: 146,
      sha256: '630eb7dfe508f0a1c1d3f3e6a0f5b3d6c9a4b2e8f7c1d0a9b8e7f6d5c4b3a291',
      schema_version: '1.0', engine_version: '1.0.0', min_agent_version: '', origin_version: '',
      changelog: '内置规则基线快照（随包发布的初始版本）', published_by: 'system', created_at: ago(90000),
    },
    working_rule_count: 146,
    capabilities: { rulesets: true, schema_version: '1.0', engine_version: '1.0.0', max_pack_bytes: 2097152, digest: 'sha256' },
  }],
  total: 1,
}

export const ruleSetVersions = {
  items: [
    {
      id: 3, version: 'builtin-1.rollback', status: 'published', rule_count: 146,
      sha256: '630eb7dfe508f0a1c1d3f3e6a0f5b3d6c9a4b2e8f7c1d0a9b8e7f6d5c4b3a291',
      schema_version: '1.0', engine_version: '1.0.0', min_agent_version: '', origin_version: 'builtin-1',
      changelog: '回滚到 builtin-1', published_by: 'admin', created_at: ago(1200),
    },
    {
      id: 2, version: 'builtin-1', status: 'superseded', rule_count: 146,
      sha256: '630eb7dfe508f0a1c1d3f3e6a0f5b3d6c9a4b2e8f7c1d0a9b8e7f6d5c4b3a291',
      schema_version: '1.0', engine_version: '1.0.0', min_agent_version: '', origin_version: '',
      changelog: '内置规则基线快照（随包发布的初始版本）', published_by: 'system', created_at: ago(90000),
    },
  ],
  total: 2, active_version: 'builtin-1.rollback',
}

export const tasks = Array.from({ length: 15 }, (_, i) => ({
  id: 100 + i, kind: ['pcap', 'assets', 'metadata'][i % 3], status: ['Success', 'Running', 'Pending', 'Failed'][i % 4],
  progress: i % 3 === 1 ? 60 : i % 3 === 2 ? 0 : 100, current_stage: ['analyzing packets', 'discovering assets', 'extracting metadata', 'completed'][i % 4],
  log: i % 3 === 1 ? 'Parsing pcap...\nExtracting flows...' : '', payload: { pcap_id: 100 + i }, result: i % 3 === 0 ? { findings: 3 } : {},
  error: i % 4 === 3 ? 'tshark exited with code 1' : '', created_at: ago(120 - i * 6), started_at: ago(118 - i * 6), finished_at: i % 4 !== 3 ? ago(110 - i * 6) : null,
}))

export const reports = Array.from({ length: 5 }, (_, i) => ({
  id: 900 + i, title: ['数据安全检测报告', '合规基线评估报告', '网络威胁分析报告', '季度安全运营报告', 'PCAP 取证分析报告'][i],
  report_type: ['security', 'compliance', 'data'][i % 3], format: ['pdf', 'html'][i % 2],
  summary: { findings: 42, incidents: 7, assets: 128 }, storage_path: `/data/reports/report_${i}.pdf`, size: 1_200_000 + i * 200_000,
  created_at: ago(400 - i * 50),
}))

export const graph = {
  nodes: [
    { id: 'probe:1', name: 'probe-edge-1', type: 'probe', risk: 'Low', metadata: { ip: '10.0.0.10' } },
    ...assets.slice(0, 5).map((a) => ({ id: `asset:${a.id}`, name: a.ip, type: 'host', risk: a.risk_level, metadata: { hostname: a.hostname, service: a.service } })),
    ...dataAssets.slice(0, 4).map((d) => ({ id: `data:${d.id}`, name: d.name, type: 'data_asset', risk: d.sensitivity, metadata: {} })),
    { id: 'ioc:600', name: '185.220.101.77', type: 'ioc', risk: 'High', metadata: {} },
    { id: 'incident:700', name: '攻击链：资产 10.0.0.20 -> recon -> c2', type: 'incident', risk: 'Critical', metadata: {} },
  ],
  relations: [
    { source_node: 'probe:1', target_node: 'asset:300', relation: 'collects', risk: 'Low' },
    { source_node: 'asset:300', target_node: 'data:400', relation: 'holds', risk: 'High' },
    { source_node: 'asset:301', target_node: 'ioc:600', relation: 'contacted', risk: 'High' },
    { source_node: 'asset:300', target_node: 'incident:700', relation: 'involved', risk: 'Critical' },
    { source_node: 'data:402', target_node: 'incident:700', relation: 'exfil', risk: 'Critical' },
  ],
}

export const auditSummary = { asset_count: 128, file_count: 342, pcap_count: 56, anomaly_count: 87, high_risk_count: 64, overall_risk: 'High' }

// ---------------------------------------------------------------------------
// 数据安全态势大屏 (demo mode only)
// ---------------------------------------------------------------------------

export const dashboardOverview = {
  generated_at: iso(now),
  alerts: { total: 162, today: 18, yesterday: 12, delta_pct: 50, open: 37, critical_high: 46 },
  incidents: { total: 97, today: 6, yesterday: 6, delta_pct: 0, open: 21 },
  findings: { total: 979, today: 64, yesterday: 51, delta_pct: 25, high_risk: 152 },
  assets: { total: 3685, high_risk: 126, sensitive: 771, data_assets: 1280 },
  loop: { assets: 3685, findings: 979, incidents: 97, alerts: 162, reports: 18 },
  probes: { total: 12, online: 9, degraded: 1, offline: 2 },
  integrations: { total: 8, healthy: 6 },
}

export const riskDistribution = {
  risk_levels: [
    { level: 'Critical', count: 24 }, { level: 'High', count: 86 },
    { level: 'Medium', count: 412 }, { level: 'Low', count: 457 },
  ],
  severity: [
    { severity: 'Critical', count: 18 }, { severity: 'High', count: 214 },
    { severity: 'Medium', count: 388 }, { severity: 'Low', count: 359 },
  ],
  asset_types: [
    { type: 'database', count: 1482 }, { type: 'file', count: 892 },
    { type: 'host', count: 687 }, { type: 'web', count: 326 },
    { type: 'network', count: 298 },
  ],
  sensitivity: [{ sensitivity: 'High', count: 512 }, { sensitivity: 'Medium', count: 259 }],
  total_findings: 979,
  total_assets: 3685,
}

export const detectionTrend = {
  range: '7d',
  items: Array.from({ length: 7 }, (_, index) => ({
    time: iso(now - (6 - index) * 86_400_000).slice(0, 10),
    findings: [82, 96, 74, 121, 108, 143, 64][index],
    incidents: [8, 12, 9, 15, 11, 17, 6][index],
    alerts: [18, 22, 16, 27, 24, 31, 18][index],
  })),
}

export const trafficFlow = {
  generated_at: iso(now),
  days: 7,
  totals: {
    sessions: 31_027, bytes: 27_527_592_131, packets: 2_292_182,
    internal: 24_385, external: 5_996, unknown: 646,
    bytes_by_direction: { internal: 26_240_804_819, external: 286_744_388, unknown: 42_924 },
  },
  nodes: [
    { id: 'ip:10.10.0.10', ip: '10.10.0.10', name: 'core-db-01', kind: 'asset', bucket: 'internal', asset_id: 1, hostname: 'core-db-01', os: 'CentOS 7', port: 3306, service: 'mysql', asset_type: 'database', risk_level: 'High', sensitive_categories: ['personal', 'finance'], sessions: 8210, bytes: 9_203_871_234, packets: 421_002, external_sessions: 0, data_assets: 12, findings: 42, high_risk_findings: 11, incidents: 3 },
    { id: 'ip:10.10.0.21', ip: '10.10.0.21', name: 'app-web-02', kind: 'asset', bucket: 'internal', asset_id: 2, hostname: 'app-web-02', os: 'Ubuntu 22.04', port: 443, service: 'https', asset_type: 'web', risk_level: 'Medium', sensitive_categories: ['personal'], sessions: 5120, bytes: 3_881_204_112, packets: 208_331, external_sessions: 210, data_assets: 4, findings: 18, high_risk_findings: 3, incidents: 1 },
    { id: 'ip:10.10.4.7', ip: '10.10.4.7', name: '10.10.4.7', kind: 'host', bucket: 'internal', asset_id: null, hostname: '', os: '', port: 0, service: '', asset_type: '', risk_level: '', sensitive_categories: [], sessions: 3180, bytes: 1_204_881_223, packets: 96_221, external_sessions: 0, data_assets: 0, findings: 6, high_risk_findings: 0, incidents: 0 },
    { id: 'ip:10.10.7.33', ip: '10.10.7.33', name: 'file-srv-01', kind: 'asset', bucket: 'internal', asset_id: 3, hostname: 'file-srv-01', os: 'Windows Server 2019', port: 445, service: 'smb', asset_type: 'file', risk_level: 'Critical', sensitive_categories: ['personal', 'contract'], sessions: 2410, bytes: 902_331_004, packets: 71_004, external_sessions: 0, data_assets: 31, findings: 55, high_risk_findings: 22, incidents: 5 },
    { id: 'ip:10.10.2.5', ip: '10.10.2.5', name: 'share-srv-03', kind: 'asset', bucket: 'internal', asset_id: 4, hostname: 'share-srv-03', os: 'CentOS 8', port: 2049, service: 'nfs', asset_type: 'file', risk_level: 'Low', sensitive_categories: [], sessions: 1420, bytes: 480_221_003, packets: 33_120, external_sessions: 0, data_assets: 7, findings: 4, high_risk_findings: 1, incidents: 0 },
    { id: 'ip:203.0.113.24', ip: '203.0.113.24', name: '203.0.113.24', kind: 'external', bucket: 'country', asset_id: null, hostname: '', os: '', port: 443, service: 'https', asset_type: '', risk_level: '', sensitive_categories: [], sessions: 412, bytes: 188_221_004, packets: 12_884, external_sessions: 412, data_assets: 0, findings: 9, high_risk_findings: 6, incidents: 2 },
    { id: 'ip:198.51.100.19', ip: '198.51.100.19', name: '198.51.100.19', kind: 'external', bucket: 'country', asset_id: null, hostname: '', os: '', port: 443, service: 'https', asset_type: '', risk_level: '', sensitive_categories: [], sessions: 128, bytes: 54_002_887, packets: 4_031, external_sessions: 128, data_assets: 0, findings: 2, high_risk_findings: 1, incidents: 0 },
  ],
  links: [
    { source: 'ip:10.10.0.10', target: 'ip:10.10.0.21', src_ip: '10.10.0.10', dst_ip: '10.10.0.21', sessions: 1830, bytes: 4_204_881_233, packets: 190_004, direction: 'internal', bucket: 'internal' },
    { source: 'ip:10.10.0.21', target: 'ip:10.10.0.10', src_ip: '10.10.0.21', dst_ip: '10.10.0.10', sessions: 1610, bytes: 3_102_884_112, packets: 174_221, direction: 'internal', bucket: 'internal' },
    { source: 'ip:10.10.0.10', target: 'ip:10.10.7.33', src_ip: '10.10.0.10', dst_ip: '10.10.7.33', sessions: 902, bytes: 1_802_331_004, packets: 88_004, direction: 'internal', bucket: 'internal' },
    { source: 'ip:10.10.4.7', target: 'ip:10.10.2.5', src_ip: '10.10.4.7', dst_ip: '10.10.2.5', sessions: 640, bytes: 802_221_003, packets: 44_120, direction: 'internal', bucket: 'internal' },
    { source: 'ip:10.10.4.7', target: 'ip:203.0.113.24', src_ip: '10.10.4.7', dst_ip: '203.0.113.24', sessions: 412, bytes: 188_221_004, packets: 12_884, direction: 'external', bucket: 'country' },
    { source: 'ip:10.10.0.21', target: 'ip:198.51.100.19', src_ip: '10.10.0.21', dst_ip: '198.51.100.19', sessions: 128, bytes: 54_002_887, packets: 4_031, direction: 'external', bucket: 'country' },
  ],
  trend: Array.from({ length: 7 }, (_, index) => ({
    time: iso(now - (6 - index) * 86_400_000).slice(5, 10),
    internal: [18_420, 19_880, 20_140, 22_310, 21_940, 24_385, 20_110][index],
    external: [4_120, 4_680, 4_910, 5_240, 5_610, 5_996, 4_980][index],
    unknown: [320, 410, 380, 460, 590, 646, 502][index],
  })),
}
