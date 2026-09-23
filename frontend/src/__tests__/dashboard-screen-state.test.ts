import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import {
  engineCategory, engineState, levelBreakdown, shortDay, useDashboardScreen,
} from '../modules/dashboard/composables/useDashboardScreen'
import type { Alert } from '../types/alert'
import type { DashboardOverview, GeoDistribution, RiskDistribution, TrafficFlow } from '../types/dashboard'
import type { IntegrationStatus } from '../types/integration'
import type { Probe } from '../api/probes'
import * as dashboard from '../api/dashboard'
import * as integrations from '../api/integrations'

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
  integrations: { total: 8, healthy: 3 },
}

const traffic: TrafficFlow = {
  generated_at: '2026-09-22T12:00:00Z',
  days: 7,
  totals: {
    sessions: 36481, bytes: 1024, packets: 512,
    internal: 30000, external: 6000, unknown: 481,
    bytes_by_direction: { internal: 800, external: 200, unknown: 24 },
  },
  nodes: [
    { id: 'n1', ip: '10.0.0.9', name: 'db-01', kind: 'asset', bucket: 'internal', asset_id: 3,
      hostname: 'db-01', os: 'Linux', port: 5432, service: 'postgres', asset_type: 'database',
      risk_level: 'High', sensitive_categories: ['个人信息'], sessions: 900, bytes: 500,
      packets: 300, external_sessions: 0, data_assets: 4, findings: 12, high_risk_findings: 3,
      incidents: 2 },
  ],
  links: [
    { source: 'n1', target: 'n2', src_ip: '10.0.0.9', dst_ip: '10.0.0.5', sessions: 400,
      bytes: 100, packets: 60, direction: 'internal', bucket: 'internal' },
  ],
  trend: [
    { time: '09-16', internal: 10, external: 2, unknown: 0 },
    { time: '09-17', internal: 12, external: 1, unknown: 1 },
  ],
}

const risk: RiskDistribution = {
  risk_levels: [
    { level: 'High', count: 12 }, { level: 'Critical', count: 3 },
    { level: 'Low', count: 0 }, { level: 'Info', count: 2 },
  ],
  severity: [],
  asset_types: [{ type: 'database', count: 4 }, { type: 'host', count: 2 }, { type: 'network', count: 0 }],
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
    { key: 'internal', label: '内网', hosts: 3, sessions: 900, bytes: 50000,
      level_counts: { L4: 3 } },
    { key: 'domestic', label: '国内', hosts: 1, sessions: 120, bytes: 9000,
      level_counts: { L2: 1 } },
    { key: 'overseas', label: '境外', hosts: 2, sessions: 80, bytes: 4000,
      level_counts: { L3: 2 } },
    { key: 'unknown', label: '未评级', hosts: 1, sessions: 5, bytes: 100, level_counts: {} },
  ],
  points: [
    { id: 'internal', region: 'internal', region_label: '内网', country: '', country_name: '内网',
      sample_host: '10.0.0.9', hosts: 3, sessions: 900, bytes: 50000, packets: 3000,
      level: 'L4', level_label: 'L4', level_counts: { L4: 3 }, lat: null, lon: null },
    { id: 'CN', region: 'domestic', region_label: '国内', country: 'CN', country_name: '中国',
      sample_host: '114.114.114.114', hosts: 1, sessions: 120, bytes: 9000, packets: 500,
      level: 'L2', level_label: 'L2', level_counts: { L2: 1 }, lat: 35.0, lon: 105.0 },
    { id: 'US', region: 'overseas', region_label: '境外', country: 'US', country_name: '美国',
      sample_host: '185.199.110.133', hosts: 2, sessions: 80, bytes: 4000, packets: 200,
      level: 'L3', level_label: 'L3', level_counts: { L3: 2 }, lat: 39.8, lon: -98.6 },
  ],
  totals: { sessions: 1105, bytes: 63100, packets: 3700, hosts: 7, level_counts: { L4: 3, L3: 2, L2: 1 } },
}

const integration = (overrides: Partial<IntegrationStatus>): IntegrationStatus => ({
  name: 'zeek', adapter_version: '', version: '6.0', installed: true, enabled: true, healthy: true,
  runtime_version: '', supported_types: [], capabilities: [], last_check: '', status: '', message: '',
  ...overrides,
})

const alert = (id: number, overrides: Partial<Alert> = {}): Alert => ({
  id, fingerprint: `f${id}`, severity: 'High', risk_score: 70, title: '发现敏感文件外发',
  summary: '', status: 'new', first_seen: '2026-09-22T12:20:00', last_seen: '2026-09-22T12:20:00',
  occurrence_count: 1, source: 'probe', created_at: '', updated_at: '', ...overrides,
})

const probe: Probe = {
  id: 1, name: 'test123', hostname: 'probe-1', ip_address: '192.168.191.130', status: 'online',
  last_seen: '2026-09-22T12:19:00', metadata: {}, created_at: '',
}

let state: ReturnType<typeof useDashboardScreen>
let app: App
let host: HTMLElement

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountScreen = async () => {
  const Harness = defineComponent({
    setup() {
      state = useDashboardScreen({ refreshMs: 0, topologyLimit: 3 })
      return () => null
    },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(Harness)
  app.mount(host)
  await flushing()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(dashboard.getDashboardOverview).mockResolvedValue(overview)
  vi.mocked(dashboard.getTrafficFlow).mockResolvedValue(traffic)
  vi.mocked(dashboard.getRiskDistribution).mockResolvedValue(risk)
  vi.mocked(dashboard.getDetectionTrend).mockResolvedValue({
    range: '7d',
    items: [
      { time: '09-21', findings: 10, incidents: 2, alerts: 4 },
      { time: '09-22', findings: 20, incidents: 3, alerts: 6 },
    ],
  })
  vi.mocked(dashboard.getRecentAlerts).mockResolvedValue([alert(2), alert(1)])
  vi.mocked(dashboard.getProbeStatus).mockResolvedValue({ items: [probe], total: 1, page: 1, page_size: 100 })
  vi.mocked(dashboard.getDashboardEngines).mockResolvedValue({
    items: [{ engine: 'zeek', count: 5 }, { engine: 'suricata', count: 9 }, { engine: 'misp', count: 3 }],
  })
  vi.mocked(dashboard.getGeoMap).mockResolvedValue(geo)
  vi.mocked(integrations.listIntegrations).mockResolvedValue([
    integration({ name: 'zeek', capabilities: ['conn', 'dns'] }),
    integration({ name: 'suricata', healthy: false, supported_types: ['pcap', 'alert'] }),
    integration({ name: 'presidio', enabled: false, healthy: false }),
    integration({ name: 'misp', capabilities: ['ip', 'domain'] }),
  ])
})

afterEach(() => {
  app.unmount()
  host.remove()
})

describe('数据安全态势大屏 state', () => {
  it('loads every panel from the server aggregate', async () => {
    await mountScreen()
    expect(state.overview.value?.alerts.total).toBe(166)
    expect(state.overview.value?.probes.online).toBe(1)
    expect(state.traffic.value?.totals.sessions).toBe(36481)
    expect(state.risk.value?.total_findings).toBe(3313)
    expect(state.events.value).toHaveLength(2)
    expect(state.probes.value[0].name).toBe('test123')
    expect(state.integrations.value).toHaveLength(4)
    expect(state.geo.value?.points).toHaveLength(3)
    expect(state.geo.value?.points[1].country_name).toBe('中国')
    expect(state.error.value).toBe('')
    expect(state.loading.value).toBe(false)
    expect(state.updatedAt.value).not.toBeNull()
  })

  it('loads the geo map alongside the other panels', async () => {
    await mountScreen()
    // The marker budget is the API's own default; the panel must not widen it.
    expect(dashboard.getGeoMap).toHaveBeenCalledTimes(1)
    expect(dashboard.getGeoMap).toHaveBeenCalledWith()
    expect(state.geo.value?.totals.hosts).toBe(7)
    expect(state.geo.value?.regions.map((region) => region.key))
      .toEqual(['internal', 'domestic', 'overseas', 'unknown'])
  })

  it('asks the topology for exactly the links the card can draw', async () => {
    await mountScreen()
    expect(dashboard.getTrafficFlow).toHaveBeenCalledWith({ limit: 3, days: 7 })
    expect(state.nodes.value).toHaveLength(1)
    expect(state.links.value[0].direction).toBe('internal')
    expect(state.flowX.value).toEqual(['09-16', '09-17'])
  })

  it('keeps the four-level severity scale and drops empty levels', async () => {
    await mountScreen()
    // Critical -> High order, the zero Low level drops out, and a level the API
    // reports but the scale does not know (Info) keeps its slice.
    expect(state.riskSlices.value.map((slice) => slice.name)).toEqual(['严重', '高危', 'Info'])
    expect(state.riskSlices.value.map((slice) => slice.value)).toEqual([3, 12, 2])
    expect(state.riskSlices.value[0].color).toBe('#ef4444')
    expect(state.riskSlices.value[2].color).toBeUndefined()
  })

  it('orders the asset donut by count and drops empty types', async () => {
    await mountScreen()
    expect(state.assetSlices.value.map((slice) => [slice.name, slice.value])).toEqual([
      ['数据库', 4], ['主机', 2],
    ])
  })

  it('labels an engine by whether the platform actually runs it', async () => {
    await mountScreen()
    expect(state.engineRows.value.map((row) => row.label)).toEqual(['Zeek', 'MISP', 'Suricata', 'Presidio'])
    expect(state.engineRows.value.map((row) => row.state)).toEqual(['running', 'running', 'error', 'stopped'])
    expect(state.engineRows.value.map((row) => row.category))
      .toEqual(['流量分析', '情报匹配', '流量分析', '适配器'])
    expect(state.engineRows.value[0].findings).toBe(5)
    expect(state.engineSummary.value).toEqual({ total: 4, running: 2, error: 1, stopped: 1 })
  })

  it('switches the detection trend between findings, incidents and alerts', async () => {
    await mountScreen()
    expect(state.detectionLabel.value).toBe('检测发现')
    expect(state.detectionValues.value).toEqual([10, 20])
    state.metric.value = 'alerts'
    await nextTick()
    expect(state.detectionLabel.value).toBe('安全告警')
    expect(state.detectionValues.value).toEqual([4, 6])
  })

  it('shows the closed loop from the platform rows, not a made-up funnel', async () => {
    await mountScreen()
    expect(state.loop.value).toEqual({ assets: 7, findings: 3313, incidents: 97, alerts: 166, reports: 0 })
  })

  it('surfaces a failed load instead of pretending the wall has data', async () => {
    vi.mocked(dashboard.getDashboardOverview).mockRejectedValue(new Error('503 Service Unavailable'))
    await mountScreen()
    expect(state.error.value).toBe('503 Service Unavailable')
    expect(state.overview.value).toBeNull()
    expect(state.loading.value).toBe(false)
  })
})

describe('大屏 helper projections', () => {
  it('classifies an adapter state from enabled + healthy', () => {
    expect(engineState(integration({ enabled: false, healthy: true }))).toBe('stopped')
    expect(engineState(integration({ enabled: true, healthy: false }))).toBe('error')
    expect(engineState(integration({ enabled: true, healthy: true }))).toBe('running')
  })

  it('shortens an ISO day for the axis without touching anything else', () => {
    expect(shortDay('2026-09-22')).toBe('09-22')
    expect(shortDay('09-22')).toBe('09-22')
    expect(shortDay('')).toBe('')
  })

  it('falls back to the raw level and the raw type when it has no label', () => {
    expect(levelBreakdown([{ level: 'Weird', count: 1 }], 'level')[0].name).toBe('Weird')
    expect(engineCategory(integration({ capabilities: ['something-new'] }))).toBe('适配器')
  })
})
