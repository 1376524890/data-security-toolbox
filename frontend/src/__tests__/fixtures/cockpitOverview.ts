/**
 * The 驾驶舱 fixtures: one overview, one trend and three task rows, shaped
 * exactly like the server's response.
 *
 * The values are the real ones the platform currently stores (3 685 assets,
 * 979 findings, 97 incidents, 162 alerts) so a test failure reads as a change
 * in the projection rather than a change in the sample numbers. Both cockpit
 * tests share them, so the page test and the state test can never disagree
 * about what the server sent.
 */
import type { CockpitOverview, CockpitTrend } from '../../types/dashboard'
import type { Task } from '../../types/task'

export const cockpitOverview: CockpitOverview = {
  generated_at: '2026-09-22T12:00:00Z',
  alerts: { total: 162, today: 12, yesterday: 0, delta_pct: null, open: 62, critical_high: 9 },
  incidents: { total: 97, today: 3, yesterday: 5, delta_pct: -40, open: 22 },
  findings: { total: 979, today: 120, yesterday: 100, delta_pct: 20, high_risk: 441 },
  assets: { total: 7, high_risk: 2, sensitive: 0, data_assets: 0 },
  loop: { assets: 3685, findings: 979, incidents: 97, alerts: 162, reports: 24 },
  probes: { total: 12, online: 12, degraded: 0, offline: 0 },
  integrations: { total: 8, healthy: 5 },
  asset_count: 3685,
  data_asset_count: 771,
  network_asset_count: 2793,
  finding_count: 979,
  incident_count: 97,
  alert_count: 162,
  high_risk_count: 441,
  egress_event_count: 44,
  health_score: {
    score: 78.6,
    grade: '一般',
    components: [
      { key: 'asset_safety', label: '资产安全', score: 82, numerator: 5, denominator: 7,
        detail: '非高风险资产 5 / 资产 7' },
      { key: 'data_protection', label: '数据防护', score: 76, numerator: 586, denominator: 771,
        detail: '非高敏对象 586 / 数据对象 771' },
      { key: 'detection_response', label: '检测响应', score: 81, numerator: 134, denominator: 166,
        detail: '已处置告警 134 / 告警 166' },
      { key: 'compliance', label: '合规管理', score: 73, numerator: null, denominator: null,
        detail: '四项检查完成度均值（4 项有分母）' },
    ],
    weights: {
      asset_safety: 0.25, data_protection: 0.25, detection_response: 0.25, compliance: 0.25,
    },
  },
  risk_distribution: {
    risk_levels: [
      { name: 'High', count: 279 }, { name: 'Critical', count: 162 },
      { name: 'Medium', count: 385 }, { name: 'Low', count: 153 },
      { name: 'Info', count: 4 },
    ],
    severity: [],
    // ``DataObject.sensitivity`` carries the console's four-level scale, so the
    // card prints 严重/高危/中危/低危 like every other surface does.
    data_sensitivity: [
      { name: 'High', count: 12 }, { name: 'Low', count: 500 }, { name: 'Critical', count: 3 },
    ],
    total_findings: 979,
  },
  asset_distribution: {
    asset_types: [
      { name: 'host', count: 1245 }, { name: 'database', count: 771 },
      { name: 'network', count: 438 }, { name: 'unknown-slug', count: 12 },
    ],
    network_types: [{ name: 'service', count: 20 }],
    total_assets: 3685,
    total_network_assets: 2793,
  },
  compliance_progress: {
    rate: 85,
    passed: 2,
    measured: 4,
    checks: [
      { key: 'classification', label: '数据分类分级', numerator: 616, denominator: 771,
        rate: 80, detail: '命中敏感类目并完成分级的对象' },
      { key: 'sensitive_protection', label: '敏感数据保护', numerator: 12, denominator: 12,
        rate: 100, detail: '高敏实例中采集覆盖完整的' },
      { key: 'egress', label: '数据出境', numerator: 44, denominator: 73, rate: 60,
        detail: '非内网会话中已判定去向的' },
      { key: 'permission', label: '权限管理', numerator: 0, denominator: 0, rate: null,
        detail: '已上报文件权限的实例' },
    ],
  },
  flow: {
    totals: {
      internal: { sessions: 30100, bytes: 1024, destinations: 8 },
      external: { sessions: 44, bytes: 512, destinations: 4 },
      unknown: { sessions: 602, bytes: 256, destinations: 3 },
    },
    weekly: {
      internal: { week: 602, prev_week: 690, delta_pct: -13 },
      external: { week: 44, prev_week: 34, delta_pct: 29 },
      unknown: { week: 12, prev_week: 0, delta_pct: null },
    },
  },
  focus: [
    { key: 'high_risk', label: '高风险项', value: 441, unit: '项', hint: '需立即处理',
      delta_pct: -50 },
    { key: 'incidents', label: '新增安全事件', value: 97, unit: '条', hint: '较上周 +23%',
      delta_pct: 23 },
    { key: 'egress', label: '数据外发事件', value: 44, unit: '个', hint: '较上周 +29%',
      delta_pct: 29 },
    { key: 'alerts', label: '未处理告警', value: 62, unit: '条', hint: '需及时处理',
      delta_pct: null },
    { key: 'compliance', label: '合规检查完成率', value: 85, unit: '%',
      hint: '仍有 2 项未达 100%', delta_pct: null },
  ],
  status: [
    { key: 'probes', label: '探针状态', up: 12, total: 12, rate: 100, detail: '在线探针' },
    { key: 'integrations', label: '集成组件', up: 5, total: 8, rate: 62.5, detail: '健康适配器' },
    { key: 'engines', label: '检测引擎', up: 4, total: 4, rate: 100, detail: '近 7 天有产出的引擎' },
    { key: 'collection', label: '数据采集', up: 6, total: 6, rate: 100, detail: '近 7 天采集任务完成' },
  ],
  trends: {
    asset_count: { week: 20, prev_week: 18, delta_pct: 11 },
    data_asset_count: { week: 60, prev_week: 55, delta_pct: 9 },
    network_asset_count: { week: 300, prev_week: 260, delta_pct: 15 },
    finding_count: { week: 120, prev_week: 113, delta_pct: 6 },
    incident_count: { week: 97, prev_week: 79, delta_pct: 23 },
    alert_count: { week: 162, prev_week: 137, delta_pct: 18 },
    high_risk_count: { week: 44, prev_week: 88, delta_pct: -50 },
    egress_event_count: { week: 44, prev_week: 34, delta_pct: 29 },
  },
}

export const cockpitTrend: CockpitTrend = {
  range: '7d',
  items: [
    { time: '2026-09-21', findings: 10, incidents: 2, alerts: 4, internal: 300, external: 6, unknown: 1 },
    { time: '2026-09-22', findings: 20, incidents: 3, alerts: 6, internal: 302, external: 8, unknown: 0 },
  ],
}

const task = (overrides: Partial<Task>): Task => ({
  id: 1, kind: 'scan', status: 'Success', progress: 100, current_stage: '', log: '',
  payload: {}, result: {}, error: '', created_at: '2026-09-22T02:30:00', ...overrides,
})

export const cockpitTasks: Task[] = [
  task({ id: 3, kind: 'file_source_scan', status: 'Partial',
         payload: { config: { name: '192.168.110.168 检查采集 /home' } },
         started_at: '2026-09-22T03:58:50' }),
  task({ id: 2, payload: { target: '192.168.110.168' }, started_at: null }),
  task({ id: 1, kind: 'brand_new_kind', payload: { probe_id: 9 } }),
]
