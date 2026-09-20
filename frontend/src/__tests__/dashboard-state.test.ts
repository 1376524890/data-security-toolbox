import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { useDashboard } from '../modules/dashboard/composables/useDashboard'
import type { DashboardSummary } from '../types/dashboard'
import type { RiskSummary } from '../api/risk'
import type { HealthResponse } from '../api/health'
import type { Incident } from '../types/incident'
import type { Asset } from '../types/asset'
import { severityTagColors } from '../utils/mapping'
import * as dashboard from '../api/dashboard'
import * as risk from '../api/risk'
import * as health from '../api/health'

vi.mock('../api/dashboard', () => ({
  getDashboardSummary: vi.fn(), getRiskTrend: vi.fn(), getIncidentTrend: vi.fn(),
  getDashboardSeverity: vi.fn(), getDashboardEngines: vi.fn(), getDashboardIncidents: vi.fn(),
  getHighRiskAssets: vi.fn(), getSensitiveData: vi.fn(),
}))
vi.mock('../api/risk', () => ({ getRiskSummary: vi.fn() }))
vi.mock('../api/health', () => ({ getHealth: vi.fn() }))

const summary = (overrides: Partial<DashboardSummary> = {}): DashboardSummary => ({
  assets: 214, files: 12, pcaps: 9, anomalies: 3, tasks: 40, reports: 2, probes: 1, incidents: 208,
  iocs: 55, alerts: 478, open_alerts: 63, high_risk_findings: 120, open_incidents: 17,
  high_risk_assets: 31, sensitive_data_assets: 44, online_probes: 1, healthy_integrations: 4, ...overrides,
})

const riskSummary = (overrides: Partial<RiskSummary> = {}): RiskSummary => ({
  count: 40, risk_levels: { Critical: 3, High: 7, Medium: 11, Low: 19 }, engines: {}, asset_risk: {},
  data_sensitivity: {}, max_score: 96.5, avg_score: 41.2, ...overrides,
})

const healthResponse = (overrides: Partial<HealthResponse> = {}): HealthResponse => ({
  status: 'ok', service: 'api', api: '1.0.0', database: 'ok', redis: 'ok',
  celery: { broker: 'redis', workers: 1, running: 0, queued: 0 }, analysis_worker: 'ready',
  worker_capabilities: [], tshark: { available: true, version: '4.0' },
  zeek: { available: false, version: '' }, suricata: { available: false, version: '', rule_count: 0 },
  storage_usage_bytes: 0, storage_max_bytes: 0,
  queue: { pending: 2, running: 1, oldest_pending_age: 5 },
  probe: { count: 1, online: 1, degraded: 0, offline: 0, auth_error: 0 }, ...overrides,
})

const incident = (overrides: Partial<Incident> = {}): Incident => ({
  id: 207, title: '可疑外联', severity: 'High', confidence: 0.8, status: 'open',
  findings: { items: [] }, evidence: { stages: ['unknown'] }, risk_score: 72, risk_level: 'High',
  timestamp: '2026-09-19T10:00:00', created_at: '2026-09-19T10:00:00', ...overrides,
})

const asset = (overrides: Partial<Asset> = {}): Asset => ({
  id: 214, ip: '192.168.191.168', hostname: 'web-01', os: 'Linux', port: 443, protocol: 'tcp',
  service: 'https', asset_type: 'service', risk_level: 'High', sensitive_categories: ['personal'],
  ...overrides,
})

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async (): Promise<ReturnType<typeof useDashboard>> => {
  let state: ReturnType<typeof useDashboard>
  const Harness = defineComponent({
    setup() {
      state = useDashboard()
      return () => null
    },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(Harness)
  app.mount(host)
  await flushing()
  return state!
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(dashboard.getDashboardSummary).mockResolvedValue(summary())
  vi.mocked(risk.getRiskSummary).mockResolvedValue(riskSummary())
  vi.mocked(health.getHealth).mockResolvedValue(healthResponse())
  vi.mocked(dashboard.getRiskTrend).mockResolvedValue({
    range: '7d', items: [{ time: '09-19', count: 4, risk_score: 55.5, critical: 1, high: 3 }],
  })
  vi.mocked(dashboard.getIncidentTrend).mockResolvedValue({
    range: '7d', items: [{ time: '09-19', count: 2, critical: 0, high: 1, medium: 1, risk_score: 40 }],
  })
  vi.mocked(dashboard.getDashboardSeverity).mockResolvedValue({ items: [{ severity: 'High', count: 7 }] })
  vi.mocked(dashboard.getDashboardEngines).mockResolvedValue({
    items: [{ engine: 'suricata', count: 9 }, { engine: 'zeek', count: 4 }],
  })
  vi.mocked(dashboard.getDashboardIncidents).mockResolvedValue({ items: [incident()] })
  vi.mocked(dashboard.getHighRiskAssets).mockResolvedValue({ items: [asset()] })
  vi.mocked(dashboard.getSensitiveData).mockResolvedValue({ items: [{ category: 'personal', count: 3 }] })
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('dashboard state', () => {
  it('loads the summary, the risk, the health, the trends, the charts and the two tables together', async () => {
    const state = await mount()
    expect(dashboard.getDashboardSummary).toHaveBeenCalled()
    expect(risk.getRiskSummary).toHaveBeenCalled()
    expect(health.getHealth).toHaveBeenCalled()
    expect(dashboard.getRiskTrend).toHaveBeenCalledWith('7d')
    expect(dashboard.getIncidentTrend).toHaveBeenCalledWith('7d')
    expect(dashboard.getDashboardSeverity).toHaveBeenCalled()
    expect(dashboard.getDashboardEngines).toHaveBeenCalled()
    expect(dashboard.getDashboardIncidents).toHaveBeenCalled()
    expect(dashboard.getHighRiskAssets).toHaveBeenCalled()
    expect(dashboard.getSensitiveData).toHaveBeenCalled()
    expect(state.summary.value?.alerts).toBe(478)
    expect(state.risk.value?.max_score).toBe(96.5)
    expect(state.health.value?.queue.pending).toBe(2)
    expect(state.trend.value[0].risk_score).toBe(55.5)
    expect(state.incidentTrend.value[0].count).toBe(2)
    expect(state.incidents.value[0].title).toBe('可疑外联')
    expect(state.assets.value[0].ip).toBe('192.168.191.168')
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('keeps the risk levels in the fixed critical-to-low order and fills the missing ones with zero', async () => {
    vi.mocked(risk.getRiskSummary).mockResolvedValue(riskSummary({ risk_levels: { High: 7, Low: 19 } }))
    const state = await mount()
    expect(state.riskLevels.value).toEqual([
      { level: 'Critical', count: 0 },
      { level: 'High', count: 7 },
      { level: 'Medium', count: 0 },
      { level: 'Low', count: 19 },
    ])
  })

  it('orders the severity donut by the shared scale and colours the slices like the tags', async () => {
    vi.mocked(dashboard.getDashboardSeverity).mockResolvedValue({
      items: [{ severity: 'Low', count: 2 }, { severity: 'Critical', count: 5 }, { severity: 'High', count: 7 }],
    })
    const state = await mount()
    expect(state.severityData.value).toEqual([
      { name: '严重', value: 5, itemStyle: { color: severityTagColors.Critical } },
      { name: '高危', value: 7, itemStyle: { color: severityTagColors.High } },
      { name: '低危', value: 2, itemStyle: { color: severityTagColors.Low } },
    ])
  })

  it('drops the levels with no rows and keeps any extra level the API reports', async () => {
    vi.mocked(dashboard.getDashboardSeverity).mockResolvedValue({
      items: [{ severity: 'Medium', count: 0 }, { severity: 'Info', count: 4 }],
    })
    const state = await mount()
    expect(state.severityData.value).toEqual([{ name: 'Info', value: 4, itemStyle: { color: undefined } }])
  })

  it('breaks the sensitive-data donut down by category with the same scale', async () => {
    vi.mocked(dashboard.getSensitiveData).mockResolvedValue({
      items: [{ category: 'personal', count: 3 }, { category: 'High', count: 8 }],
    })
    const state = await mount()
    expect(state.sensitiveData.value).toEqual([
      { name: '高危', value: 8, itemStyle: { color: severityTagColors.High } },
      { name: 'personal', value: 3, itemStyle: { color: undefined } },
    ])
  })

  it('maps the engine chart into parallel x and y arrays', async () => {
    const state = await mount()
    expect(state.engineData.value).toEqual({ x: ['suricata', 'zeek'], y: [9, 4] })
  })

  it('keeps a failed dashboard load in the page state', async () => {
    vi.mocked(dashboard.getDashboardSummary).mockRejectedValue(new Error('看板服务不可用'))
    const state = await mount()
    expect(state.error.value).toBe('看板服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.summary.value).toBeNull()
  })
})
