import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import DashboardScreen from '../modules/dashboard/DashboardScreen.vue'
import type { DashboardOverview, GeoDistribution, RiskDistribution, TrafficFlow } from '../types/dashboard'
import type { IntegrationStatus } from '../types/integration'
import type { Probe } from '../api/probes'
import * as dashboard from '../api/dashboard'
import * as integrations from '../api/integrations'

const chart = vi.hoisted(() => ({
  setOption: vi.fn(), on: vi.fn(), off: vi.fn(), dispose: vi.fn(), resize: vi.fn(),
}))

vi.mock('echarts', () => {
  class LinearGradient { constructor(..._args: unknown[]) {} }
  return { init: () => chart, graphic: { LinearGradient } }
})
vi.mock('vue-router', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('../api/dashboard', () => ({
  getDashboardOverview: vi.fn(), getTrafficFlow: vi.fn(), getRiskDistribution: vi.fn(),
  getDetectionTrend: vi.fn(), getRecentAlerts: vi.fn(), getProbeStatus: vi.fn(),
  getDashboardEngines: vi.fn(), getGeoMap: vi.fn(),
}))
vi.mock('../api/integrations', () => ({ listIntegrations: vi.fn() }))

const overview: DashboardOverview = {
  generated_at: '2026-09-22T12:00:00Z',
  alerts: { total: 166, today: 12, yesterday: 0, delta_pct: null, open: 40, critical_high: 9 },
  incidents: { total: 97, today: 3, yesterday: 5, delta_pct: -40, open: 22 },
  findings: { total: 3313, today: 120, yesterday: 100, delta_pct: 20, high_risk: 410 },
  assets: { total: 7, high_risk: 2, sensitive: 0, data_assets: 0 },
  loop: { assets: 7, findings: 3313, incidents: 97, alerts: 166, reports: 0 },
  probes: { total: 1, online: 1, degraded: 0, offline: 0 },
  integrations: { total: 8, healthy: 5 },
}

const traffic: TrafficFlow = {
  generated_at: '2026-09-22T12:00:00Z',
  days: 7,
  totals: {
    sessions: 36481, bytes: 27527592131, packets: 2292182,
    internal: 30100, external: 5996, unknown: 385,
    bytes_by_direction: { internal: 27240804819, external: 286744388, unknown: 42924 },
  },
  nodes: [
    { id: 'ip:10.0.0.9', ip: '10.0.0.9', name: 'db-01', kind: 'asset', bucket: 'internal',
      asset_id: 3, hostname: 'db-01', os: 'Linux', port: 5432, service: 'postgres',
      asset_type: 'database', risk_level: 'High', sensitive_categories: ['个人信息'],
      sessions: 900, bytes: 500, packets: 300, external_sessions: 0, data_assets: 4,
      findings: 12, high_risk_findings: 3, incidents: 2 },
    { id: 'ip:185.199.110.133', ip: '185.199.110.133', name: '185.199.110.133', kind: 'external',
      bucket: 'country', asset_id: null, hostname: '', os: '', port: 0, service: '',
      asset_type: '', risk_level: '', sensitive_categories: [], sessions: 126, bytes: 90,
      packets: 60, external_sessions: 126, data_assets: 0, findings: 0, high_risk_findings: 0,
      incidents: 0 },
  ],
  links: [
    { source: 'ip:10.0.0.9', target: 'ip:185.199.110.133', src_ip: '10.0.0.9',
      dst_ip: '185.199.110.133', sessions: 126, bytes: 90, packets: 60,
      direction: 'external', bucket: 'country' },
  ],
  trend: [{ time: '09-22', internal: 10, external: 2, unknown: 0 }],
}

const risk: RiskDistribution = {
  risk_levels: [{ level: 'High', count: 500 }, { level: 'Critical', count: 479 },
    { level: 'Medium', count: 1989 }, { level: 'Low', count: 345 }],
  severity: [{ severity: 'Critical', count: 10 }],
  asset_types: [{ type: 'web', count: 3 }, { type: 'database', count: 1 }],
  sensitivity: [],
  total_findings: 3313,
  total_assets: 7,
}

const geo: GeoDistribution = {
  generated_at: '2026-09-22T12:00:00Z',
  country_table_present: true,
  unrated_label: '未评级',
  levels: [
    { key: 'L4', name: '核心/极高敏感' }, { key: 'L3', name: '高敏感个人信息' },
    { key: 'L2', name: '一般个人信息/重要业务数据' }, { key: 'L1', name: '低敏感/公开' },
  ],
  regions: [
    { key: 'internal', label: '内网', hosts: 3, sessions: 900, bytes: 50000, level_counts: { L4: 3 } },
    { key: 'domestic', label: '国内', hosts: 1, sessions: 126, bytes: 90, level_counts: { L2: 1 } },
    { key: 'overseas', label: '境外', hosts: 2, sessions: 80, bytes: 4000, level_counts: { L3: 2 } },
    { key: 'unknown', label: '未评级', hosts: 1, sessions: 5, bytes: 100, level_counts: {} },
  ],
  points: [
    { id: 'internal', region: 'internal', region_label: '内网', country: '', country_name: '内网',
      sample_host: '10.0.0.9', hosts: 3, sessions: 900, bytes: 50000, packets: 3000,
      level: 'L4', level_label: 'L4', level_counts: { L4: 3 }, lat: null, lon: null },
    { id: 'CN', region: 'domestic', region_label: '国内', country: 'CN', country_name: '中国',
      sample_host: '114.114.114.114', hosts: 1, sessions: 126, bytes: 90, packets: 60,
      level: 'L2', level_label: 'L2', level_counts: { L2: 1 }, lat: 35.0, lon: 105.0 },
    { id: 'US', region: 'overseas', region_label: '境外', country: 'US', country_name: '美国',
      sample_host: '185.199.110.133', hosts: 2, sessions: 80, bytes: 4000, packets: 200,
      level: 'L3', level_label: 'L3', level_counts: { L3: 2 }, lat: 39.8, lon: -98.6 },
  ],
  totals: { sessions: 1111, bytes: 54190, packets: 3260, hosts: 7, level_counts: { L4: 3, L3: 2, L2: 1 } },
}

const integration = (overrides: Partial<IntegrationStatus>): IntegrationStatus => ({
  name: 'zeek', adapter_version: '', version: '6.0', installed: true, enabled: true, healthy: true,
  runtime_version: '', supported_types: [], capabilities: [], last_check: '', status: '', message: '',
  ...overrides,
})

const probe: Probe = {
  id: 1, name: 'test123', hostname: 'probe-1', ip_address: '192.168.191.130', status: 'online',
  last_seen: '2026-09-22T12:19:00', metadata: {}, created_at: '',
}

let app: App
let host: HTMLElement

const stateGeoLevels = (node: HTMLElement) =>
  Array.from(node.querySelectorAll('.ds-geo .ds-legend-item'))
    .map((item) => item.textContent?.trim() || '')
    .filter((text) => text.startsWith('L'))

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountScreen = async () => {
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(DashboardScreen)
  app.use(createPinia())
  app.use(ElementPlus)
  app.mount(host)
  await flushing()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(dashboard.getDashboardOverview).mockResolvedValue(overview)
  vi.mocked(dashboard.getTrafficFlow).mockResolvedValue(traffic)
  vi.mocked(dashboard.getRiskDistribution).mockResolvedValue(risk)
  vi.mocked(dashboard.getDetectionTrend).mockResolvedValue({
    range: '7d', items: [{ time: '09-22', findings: 10, incidents: 2, alerts: 4 }],
  })
  vi.mocked(dashboard.getRecentAlerts).mockResolvedValue([{
    id: 2, fingerprint: 'f2', severity: 'High', risk_score: 70, title: '发现敏感文件外发',
    summary: '', status: 'new', first_seen: '2026-09-22T12:20:00',
    last_seen: '2026-09-22T12:20:00', occurrence_count: 1, source: '终端探针',
    created_at: '', updated_at: '',
  }])
  vi.mocked(dashboard.getProbeStatus).mockResolvedValue({
    items: [probe], total: 1, page: 1, page_size: 100,
  })
  vi.mocked(dashboard.getDashboardEngines).mockResolvedValue({ items: [{ engine: 'zeek', count: 5 }] })
  vi.mocked(dashboard.getGeoMap).mockResolvedValue(geo)
  vi.mocked(integrations.listIntegrations).mockResolvedValue([
    integration({ name: 'zeek', capabilities: ['conn'] }),
    integration({ name: 'suricata', healthy: false, supported_types: ['pcap'] }),
    integration({ name: 'presidio', enabled: false, healthy: false }),
  ])
})

afterEach(() => {
  app.unmount()
  host.remove()
})

describe('数据安全态势大屏 view', () => {
  it('renders every panel from the server aggregates', async () => {
    await mountScreen()
    const text = host.textContent || ''

    // KPI band: the six cards carry the real counters, not zeroes.
    expect(host.querySelectorAll('.ds-metric').length).toBe(6)
    expect(text).toContain('安全告警')
    expect(text).toContain('166')
    expect(text).toContain('检测发现')
    expect(text).toContain('3,313')
    expect(text).toContain('敏感数据资产')

    // Header: 集成组件 and 在线探针 come from the overview, not a second query.
    expect(host.querySelector('.ds-header')?.textContent).toContain('5/8')
    expect(text).toContain('在线探针 1')

    // Bottom row: the engine card, the probe card, the loop and the event list.
    expect(text).toContain('Zeek')
    expect(text).toContain('Suricata')
    expect(text).toContain('test123')
    expect(text).toContain('发现敏感文件外发')
    expect(text).toContain('终端探针')
    expect(text).toContain('数据更新于')
    expect(host.querySelector('.ds-overlay')).toBeNull()

    // Geo map: the four sensitivity levels are named and 内网/国内/境外 appear.
    expect(text).toContain('内网')
    expect(text).toContain('国内')
    expect(text).toContain('境外')
    expect(host.querySelectorAll('.ds-geo .ds-legend-item').length).toBe(5)
    expect(stateGeoLevels(host)).toEqual([
      'L4 核心/极高敏感', 'L3 高敏感个人信息', 'L2 一般个人信息/重要业务数据', 'L1 低敏感/公开',
    ])
    expect(host.querySelectorAll('.ds-geo-marker').length).toBeGreaterThan(0)
  })

  it('says the posture is unavailable instead of drawing an empty wall', async () => {
    vi.mocked(dashboard.getDashboardOverview).mockRejectedValue(new Error('503 Service Unavailable'))
    await mountScreen()
    expect(host.querySelector('.ds-overlay')?.textContent).toContain('态势数据不可用')
    expect(host.querySelector('.ds-overlay')?.textContent).toContain('503 Service Unavailable')
  })
})
