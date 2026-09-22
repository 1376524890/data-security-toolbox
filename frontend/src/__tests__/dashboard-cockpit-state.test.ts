import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { useDashboardCockpit } from '../modules/dashboard/cockpit/composables/useDashboardCockpit'
import type { CockpitOverview } from '../types/dashboard'
import * as dashboard from '../api/dashboard'
import { cockpitOverview as overview, cockpitTasks, cockpitTrend as trend } from './fixtures/cockpitOverview'

vi.mock('../api/dashboard', () => ({
  getCockpitOverview: vi.fn(), getCockpitTrend: vi.fn(), getCockpitTasks: vi.fn(),
}))

let state: ReturnType<typeof useDashboardCockpit>
let app: App | null = null
let host: HTMLElement

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountPage = async (refreshMs = 0) => {
  const Harness = defineComponent({
    setup() {
      state = useDashboardCockpit({ refreshMs })
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
  vi.mocked(dashboard.getCockpitOverview).mockResolvedValue(overview)
  vi.mocked(dashboard.getCockpitTrend).mockResolvedValue(trend)
  vi.mocked(dashboard.getCockpitTasks).mockResolvedValue({ items: cockpitTasks })
})

afterEach(() => {
  // The timer test unmounts by hand; a null app means there is nothing left to
  // tear down, and unmounting twice is an error in Vue.
  app?.unmount()
  app = null
  host?.remove()
})

describe('数据安全综合驾驶舱 state', () => {
  it('projects the eight KPI cards in the band order with their week deltas', async () => {
    await mountPage()
    const keys = state.metrics.value.map((item) => item.key)
    expect(keys).toEqual([
      'asset_count', 'data_asset_count', 'network_asset_count', 'finding_count',
      'incident_count', 'alert_count', 'high_risk_count', 'egress_event_count',
    ])
    const highRisk = state.metrics.value.find((item) => item.key === 'high_risk_count')!
    expect(highRisk.value).toBe(441)
    expect(highRisk.delta_pct).toBe(-50)
    expect(highRisk.riseIsBad).toBe(true)
    // A count that grows with coverage is not a failure when it rises.
    expect(state.metrics.value.find((item) => item.key === 'asset_count')!.riseIsBad).toBe(false)
    // A KPI with no rows in the previous week keeps its null: the card prints
    // "上周无数据" instead of a percentage against zero.
    vi.mocked(dashboard.getCockpitOverview).mockResolvedValue({
      ...overview,
      trends: { ...overview.trends, alert_count: { week: 5, prev_week: 0, delta_pct: null } },
    })
    await state.refresh()
    expect(state.metrics.value.find((item) => item.key === 'alert_count')!.delta_pct).toBeNull()
  })

  it('passes the server score and weights through untouched', async () => {
    await mountPage()
    expect(state.health.value?.score).toBe(78.6)
    expect(state.health.value?.weights.compliance).toBe(0.25)
    // The note names the weakest dimension the server scored, not a client guess.
    expect(state.healthNote.value).toContain('78.6')
    expect(state.healthNote.value).toContain('合规管理')
  })

  it('orders the risk ring by the console scale and keeps an unknown level', async () => {
    await mountPage()
    expect(state.riskSlices.value.map((slice) => slice.name)).toEqual([
      '严重', '高危', '中危', '低危', 'Info',
    ])
    expect(state.riskSlices.value.map((slice) => slice.value)).toEqual([162, 279, 385, 153, 4])
    expect(state.riskTotal.value).toBe(979)
  })

  it('exposes the three asset tabs with their own totals', async () => {
    await mountPage()
    expect(state.assetTabs.value.map((tab) => tab.label)).toEqual([
      '资产类型', '数据资产分级', '网络资产类型',
    ])
    const [types, sensitivity, network] = state.assetTabs.value
    expect(types.total).toBe(3685)
    // A slug the label map does not know keeps its raw value.
    expect(types.slices.map((slice) => slice.name)).toEqual(['主机', '数据库', '网络设备', 'unknown-slug'])
    expect(sensitivity.total).toBe(771)
    // 分级 uses the console's severity wording, not the raw enum.
    expect(sensitivity.slices.map((slice) => slice.name)).toEqual(['高危', '低危', '严重'])
    expect(network.total).toBe(2793)
    expect(network.slices.map((slice) => slice.name)).toEqual(['网络服务'])
  })

  it('builds the closed loop from the same totals as the KPI band', async () => {
    await mountPage()
    expect(state.pipeline.value.map((step) => [step.label, step.value])).toEqual([
      ['资产发现', 3685], ['安全发现', 979], ['安全事件', 97], ['告警处置', 162], ['分析报告', 24],
    ])
    // 分析报告 has no console page, so its node carries no destination.
    expect(state.pipeline.value[4].route).toBe('')
  })

  it('gives every known focus row a destination and falls back for a new one', async () => {
    await mountPage()
    const [highRisk, , egress, alerts, compliance] = state.focus.value
    expect(highRisk.route).toBe('/files')
    expect(highRisk.icon).toBe('WarningFilled')
    expect(egress.route).toBe('/network/dlp?view=egress')
    expect(alerts.route).toBe('/data-assets')
    expect(compliance.route).toBe('/data-assets')

    // A row the page has never seen still gets a destination (the risk list)
    // and a neutral colour rather than a dead link.
    vi.mocked(dashboard.getCockpitOverview).mockResolvedValue({
      ...overview,
      focus: [...overview.focus, { key: 'something_new', label: '新指标', value: 3,
        unit: '项', hint: '', delta_pct: null }],
    })
    await state.refresh()
    const extra = state.focus.value[5]
    expect(extra.route).toBe('/data-assets')
    expect(extra.color).toBeTruthy()
  })

  it('names tasks from their payload and never invents a kind label', async () => {
    await mountPage()
    const rows = state.taskRows.value
    expect(rows[0].name).toBe('192.168.110.168 检查采集 /home')
    expect(rows[0].kind_label).toBe('文件采集')
    expect(rows[1].name).toBe('主动扫描 192.168.110.168')
    // An unknown kind prints its raw slug and the probe it ran on.
    expect(rows[2].kind_label).toBe('brand_new_kind')
    expect(rows[2].name).toBe('brand_new_kind 探针 #9')
    expect(rows[1].started_text).not.toBe('')
  })

  it('keeps the last good numbers when a refresh fails', async () => {
    await mountPage()
    expect(state.overview.value?.asset_count).toBe(3685)
    vi.mocked(dashboard.getCockpitOverview).mockRejectedValue(new Error('网关超时'))
    await state.refresh()
    expect(state.error.value).toBe('网关超时')
    expect(state.stale.value).toBe(true)
    expect(state.overview.value?.asset_count).toBe(3685)
    // A later success clears both the banner and the stale flag.
    vi.mocked(dashboard.getCockpitOverview).mockResolvedValue(overview)
    await state.refresh()
    expect(state.error.value).toBe('')
    expect(state.stale.value).toBe(false)
  })

  it('drops a response that lost the race against a range switch', async () => {
    await mountPage()
    let release: (value: CockpitOverview) => void = () => undefined
    vi.mocked(dashboard.getCockpitOverview).mockImplementationOnce(
      () => new Promise<CockpitOverview>((resolve) => { release = resolve }),
    )
    vi.mocked(dashboard.getCockpitTrend).mockImplementation(async (range = '7d') => ({
      range, items: trend.items,
    }))
    const slow = state.refresh()
    state.setRange('24h')
    await flushing()
    // The older request finishes last and must not overwrite the newer window.
    release({ ...overview, asset_count: 1, trends: {
      ...overview.trends, asset_count: { week: 0, prev_week: 0, delta_pct: null } } })
    await slow
    await flushing()
    expect(state.overview.value?.asset_count).toBe(3685)
    expect(dashboard.getCockpitTrend).toHaveBeenLastCalledWith('24h')
    expect(state.range.value).toBe('24h')
  })

  it('stops polling once the page is gone', async () => {
    vi.useFakeTimers()
    try {
      await mountPage(1000)
      await vi.advanceTimersByTimeAsync(0)
      const calls = vi.mocked(dashboard.getCockpitOverview).mock.calls.length
      await vi.advanceTimersByTimeAsync(3000)
      expect(vi.mocked(dashboard.getCockpitOverview).mock.calls.length).toBeGreaterThan(calls)
      app?.unmount()
      app = null
      const afterUnmount = vi.mocked(dashboard.getCockpitOverview).mock.calls.length
      await vi.advanceTimersByTimeAsync(5000)
      expect(vi.mocked(dashboard.getCockpitOverview).mock.calls.length).toBe(afterUnmount)
    } finally {
      vi.useRealTimers()
    }
  })
})
