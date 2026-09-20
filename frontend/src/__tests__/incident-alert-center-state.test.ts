import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useIncidentCenter } from '../modules/operations/incidents/composables/useIncidentCenter'
import { useAlertCenter } from '../modules/operations/alerts/composables/useAlertCenter'
import type { Incident } from '../types/incident'
import type { Alert, AlertDetail, AlertSummary } from '../types/alert'
import * as alerts from '../api/alerts'
import * as incidents from '../api/incidents'

vi.mock('../api/incidents', () => ({
  listIncidents: vi.fn(), getIncident: vi.fn(), updateIncidentStatus: vi.fn(), correlateIncidents: vi.fn(),
}))
vi.mock('../api/alerts', () => ({
  listAlerts: vi.fn(), getAlert: vi.fn(), updateAlert: vi.fn(), getAlertSummary: vi.fn(),
}))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const incident = (overrides: Partial<Incident> = {}): Incident => ({
  id: 7, title: '可疑外联', severity: 'High', confidence: 0.8, status: 'open',
  findings: { items: [] }, evidence: { stages: ['recon', 'c2'] }, risk_score: 72,
  risk_level: 'High', timestamp: '2026-09-19T10:00:00', created_at: '2026-09-19T10:00:00',
  ...overrides,
})

const alert = (overrides: Partial<Alert> = {}): Alert => ({
  id: 3, fingerprint: 'f'.repeat(64), severity: 'Critical', risk_score: 90,
  title: '命中敏感外发', summary: '摘要', status: 'new', first_seen: '2026-09-19T09:00:00',
  last_seen: '2026-09-19T10:00:00', occurrence_count: 4, source: 'probe',
  created_at: '2026-09-19T09:00:00', updated_at: '2026-09-19T10:00:00', ...overrides,
})

const alertDetail = (overrides: Partial<AlertDetail> = {}): AlertDetail => ({
  alert: alert(),
  finding: { id: 1, confidence: 0.91 } as never,
  deliveries: [{ id: 1, channel: 'email', target: 'a@b.c', status: 'success', attempts: 1, last_error: '', sent_at: '2026-09-19T10:01:00' }],
  ...overrides,
})

const summary: AlertSummary = { total: 12, status: { new: 3 }, severity: { Critical: 3 }, unhandled_critical_high: 2 }

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async <T>(composable: () => T): Promise<T> => {
  let state: T
  const Harness = defineComponent({
    setup() {
      state = composable()
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
  vi.mocked(incidents.listIncidents).mockResolvedValue({ items: [incident()], total: 34, page: 1, page_size: 50 })
  vi.mocked(incidents.getIncident).mockResolvedValue(incident({ findings: { items: [{ id: 5 } as never] } }))
  vi.mocked(incidents.updateIncidentStatus).mockResolvedValue(incident({ status: 'contained' }))
  vi.mocked(incidents.correlateIncidents).mockResolvedValue([])
  vi.mocked(alerts.listAlerts).mockResolvedValue({ items: [alert()], total: 21, page: 1, page_size: 50 })
  vi.mocked(alerts.getAlert).mockResolvedValue(alertDetail())
  vi.mocked(alerts.updateAlert).mockResolvedValue(alert({ status: 'acknowledged' }))
  vi.mocked(alerts.getAlertSummary).mockResolvedValue(summary)
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('incident centre state', () => {
  it('loads the first page with the active filters and keeps the server total', async () => {
    const state = await mount(() => useIncidentCenter())
    expect(incidents.listIncidents).toHaveBeenCalledWith({
      search: '', status: '', severity: '', page: 1, page_size: 50,
    })
    expect(state.items.value.map((row) => row.id)).toEqual([7])
    expect(state.total.value).toBe(34)
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('returns to the first page when the filter bar resets', async () => {
    const state = await mount(() => useIncidentCenter())
    state.filters.search = 'c2'
    state.filters.page = 3
    vi.mocked(incidents.listIncidents).mockClear()
    state.reset()
    await flushing()
    expect(state.filters.page).toBe(1)
    expect(incidents.listIncidents).toHaveBeenCalledWith({
      search: 'c2', status: '', severity: '', page: 1, page_size: 50,
    })
  })

  it('opens the detail of the clicked row and keeps the last detail on failure', async () => {
    const state = await mount(() => useIncidentCenter())
    await state.open(incident())
    expect(state.selected.value?.id).toBe(7)
    expect(state.detail.value?.title).toBe('可疑外联')
    expect(state.detailLoading.value).toBe(false)
    expect(state.findings.value.map((item) => item.id)).toEqual([5])
    expect(state.activeStages.value).toEqual(['recon', 'c2'])

    vi.mocked(incidents.getIncident).mockRejectedValue(new Error('事件不存在'))
    await state.open(incident({ id: 9 }))
    expect(ElMessage.error).toHaveBeenCalledWith('事件不存在')
    expect(state.selected.value?.id).toBe(9)
    expect(state.detail.value?.id).toBe(7)
    expect(state.detailLoading.value).toBe(false)
  })

  it('falls back to the selected row for the attack stages', async () => {
    const state = await mount(() => useIncidentCenter())
    expect(state.activeStages.value).toEqual([])
    state.selected.value = incident({ evidence: { stages: ['exploit'] } })
    expect(state.activeStages.value).toEqual(['exploit'])
    state.selected.value = incident({ evidence: {} })
    state.detail.value = incident({ evidence: { stages: ['impact', 'exfil'] } })
    expect(state.activeStages.value).toEqual(['impact', 'exfil'])
  })

  it('updates the status, re-reads the detail and reloads the list', async () => {
    const state = await mount(() => useIncidentCenter())
    await state.open(incident())
    vi.mocked(incidents.listIncidents).mockClear()
    vi.mocked(incidents.getIncident).mockClear()
    await state.changeStatus('contained')
    expect(incidents.updateIncidentStatus).toHaveBeenCalledWith(7, 'contained')
    expect(ElMessage.success).toHaveBeenCalledWith('状态已更新为 contained')
    expect(incidents.getIncident).toHaveBeenCalledWith(7)
    expect(incidents.listIncidents).toHaveBeenCalledTimes(1)
  })

  it('does nothing when the status changes without a selected incident', async () => {
    const state = await mount(() => useIncidentCenter())
    await state.changeStatus('closed')
    expect(incidents.updateIncidentStatus).not.toHaveBeenCalled()
  })

  it('correlates a pasted findings array with the chosen window', async () => {
    const state = await mount(() => useIncidentCenter())
    state.correlateOpen.value = true
    vi.mocked(incidents.correlateIncidents).mockResolvedValue([{ id: 1 }, { id: 2 }])
    state.correlateFindings.value = '[{"rule_id":"r1"}]'
    state.correlateWindow.value = 7200
    await state.runCorrelate()
    expect(incidents.correlateIncidents).toHaveBeenCalledWith([{ rule_id: 'r1' }], 7200)
    expect(state.correlateResult.value).toHaveLength(2)
    expect(ElMessage.success).toHaveBeenCalledWith('关联完成，共生成 2 个事件')
    expect(state.correlateRunning.value).toBe(false)
  })

  it('refuses correlation without findings and for a non-array payload', async () => {
    const state = await mount(() => useIncidentCenter())
    await state.runCorrelate()
    expect(ElMessage.warning).toHaveBeenCalledWith('请输入待关联的发现 JSON')
    expect(incidents.correlateIncidents).not.toHaveBeenCalled()

    state.correlateFindings.value = '{"rule_id":"r1"}'
    await state.runCorrelate()
    expect(incidents.correlateIncidents).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('发现必须是一个数组')
    expect(state.correlateRunning.value).toBe(false)
  })

  it('reports a malformed findings payload instead of leaving the dialog spinning', async () => {
    const state = await mount(() => useIncidentCenter())
    state.correlateFindings.value = 'not json'
    await state.runCorrelate()
    expect(incidents.correlateIncidents).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalled()
    expect(state.correlateRunning.value).toBe(false)
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(incidents.listIncidents).mockRejectedValue(new Error('事件服务不可用'))
    const state = await mount(() => useIncidentCenter())
    expect(state.error.value).toBe('事件服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.items.value).toEqual([])
  })
})

describe('alert centre state', () => {
  it('loads the alert page and the summary together', async () => {
    const state = await mount(() => useAlertCenter())
    expect(alerts.listAlerts).toHaveBeenCalledWith({
      search: '', status: '', severity: '', page: 1, page_size: 50,
    })
    expect(alerts.getAlertSummary).toHaveBeenCalledWith()
    expect(state.items.value.map((row) => row.id)).toEqual([3])
    expect(state.total.value).toBe(21)
    expect(state.summary.value?.unhandled_critical_high).toBe(2)
    expect(state.loading.value).toBe(false)
  })

  it('returns to the first page when the filter bar resets', async () => {
    const state = await mount(() => useAlertCenter())
    state.filters.severity = 'Critical'
    state.filters.page = 2
    vi.mocked(alerts.listAlerts).mockClear()
    state.reset()
    await flushing()
    expect(state.filters.page).toBe(1)
    expect(alerts.listAlerts).toHaveBeenCalledWith({
      search: '', status: '', severity: 'Critical', page: 1, page_size: 50,
    })
  })

  it('opens the alert detail and exposes the finding confidence', async () => {
    const state = await mount(() => useAlertCenter())
    expect(state.confidence.value).toBeUndefined()
    await state.open(alert())
    expect(alerts.getAlert).toHaveBeenCalledWith(3)
    expect(state.selected.value?.id).toBe(3)
    expect(state.detail.value?.deliveries).toHaveLength(1)
    expect(state.confidence.value).toBe(0.91)
    expect(state.detailLoading.value).toBe(false)
  })

  it('shows the server reason when the detail cannot be read', async () => {
    vi.mocked(alerts.getAlert).mockRejectedValue(new Error('告警已归档'))
    const state = await mount(() => useAlertCenter())
    await state.open(alert())
    expect(ElMessage.error).toHaveBeenCalledWith('告警已归档')
    expect(state.detail.value).toBeNull()
    expect(state.detailLoading.value).toBe(false)
  })

  it('marks the alert and reloads both the detail and the list', async () => {
    const state = await mount(() => useAlertCenter())
    await state.open(alert())
    vi.mocked(alerts.listAlerts).mockClear()
    vi.mocked(alerts.getAlert).mockClear()
    await state.changeStatus('acknowledged')
    expect(alerts.updateAlert).toHaveBeenCalledWith(3, { status: 'acknowledged' })
    expect(ElMessage.success).toHaveBeenCalledWith('已标记为 acknowledged')
    expect(alerts.getAlert).toHaveBeenCalledWith(3)
    expect(alerts.listAlerts).toHaveBeenCalledTimes(1)
  })

  it('does nothing when the status changes without a selected alert', async () => {
    const state = await mount(() => useAlertCenter())
    await state.changeStatus('resolved')
    expect(alerts.updateAlert).not.toHaveBeenCalled()
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(alerts.listAlerts).mockRejectedValue(new Error('告警服务不可用'))
    const state = await mount(() => useAlertCenter())
    expect(state.error.value).toBe('告警服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.items.value).toEqual([])
  })
})
