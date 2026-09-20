import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useAssetCenter } from '../modules/asset/composables/useAssetCenter'
import type { Asset, AssetDetail } from '../types/asset'
import * as assets from '../api/assets'
import * as probes from '../api/probes'
import * as scan from '../api/scan'

vi.mock('../api/assets', () => ({ listAssets: vi.fn(), getAsset: vi.fn() }))
vi.mock('../api/probes', () => ({ listProbes: vi.fn() }))
vi.mock('../api/scan', () => ({ startScan: vi.fn(), getScan: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const asset = (overrides: Partial<Asset> = {}): Asset => ({
  id: 11, ip: '192.168.110.10', hostname: 'web-01', os: 'Ubuntu 22.04', port: 443,
  protocol: 'tcp', service: 'https', asset_type: 'server', risk_level: 'High',
  sensitive_categories: ['personal'], ...overrides,
})

const assetDetail = (overrides: Partial<AssetDetail> = {}): AssetDetail => ({
  asset: asset(), findings: [], incidents: [], data_assets: [], iocs: [], relations: [], ...overrides,
})

const probe = (overrides: Partial<probes.Probe> = {}): probes.Probe => ({
  id: 2, name: 'probe-a', hostname: 'probe-a', ip_address: '10.0.0.2', status: 'online',
  metadata: {}, created_at: '2026-09-19T09:00:00', ...overrides,
})

const task = (overrides: Record<string, unknown> = {}): scan.ScanResult => ({
  id: 5, status: 'Success', progress: 100, current_stage: 'done',
  result: { assets: 4, alive_hosts: 3 }, ...overrides,
} as unknown as scan.ScanResult)

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async (): Promise<ReturnType<typeof useAssetCenter>> => {
  let state: ReturnType<typeof useAssetCenter>
  const Harness = defineComponent({
    setup() {
      state = useAssetCenter()
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

// The scan console sleeps three seconds between polls, so the polling tests run
// on fake timers and step the clock instead of waiting.
const runScan = async (state: ReturnType<typeof useAssetCenter>, polls = 6) => {
  const done = state.runScan()
  await vi.advanceTimersByTimeAsync(0)
  for (let i = 0; i < polls; i += 1) await vi.advanceTimersByTimeAsync(3000)
  await done
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(assets.listAssets).mockResolvedValue({ items: [asset()], total: 34, page: 1, page_size: 50 })
  vi.mocked(assets.getAsset).mockResolvedValue(assetDetail())
  vi.mocked(probes.listProbes).mockResolvedValue({ items: [probe()], total: 1, page: 1, page_size: 200 })
  vi.mocked(scan.startScan).mockResolvedValue(task({ status: 'Running', progress: 5 }))
  vi.mocked(scan.getScan).mockResolvedValue(task())
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
  if (vi.isFakeTimers()) vi.useRealTimers()
})

describe('asset centre list and detail', () => {
  it('loads the first page on mount with the active filters and keeps the server total', async () => {
    const state = await mount()
    expect(assets.listAssets).toHaveBeenCalledWith({ risk: '', asset_type: '', search: '', page: 1, page_size: 50 })
    expect(state.items.value).toHaveLength(1)
    expect(state.total.value).toBe(34)
    expect(state.loading.value).toBe(false)
  })

  it('loads the probes for the probe-scan selector with only the fields the option label uses', async () => {
    const state = await mount()
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(state.probes.value).toEqual([{ id: 2, name: 'probe-a', ip_address: '10.0.0.2', status: 'online' }])
  })

  it('keeps the probe list empty when the probe request fails', async () => {
    vi.mocked(probes.listProbes).mockRejectedValue(new Error('探针服务不可用'))
    const state = await mount()
    expect(state.probes.value).toEqual([])
    expect(state.error.value).toBe('')
  })

  it('returns to the first page when the filter bar resets', async () => {
    const state = await mount()
    state.filters.search = 'web'
    state.filters.page = 3
    state.reset()
    await flushing()
    expect(assets.listAssets).toHaveBeenLastCalledWith({ risk: '', asset_type: '', search: 'web', page: 1, page_size: 50 })
  })

  it('opens the detail of the clicked row and returns to the basic tab', async () => {
    const state = await mount()
    state.activeTab.value = 'graph'
    await state.open(asset())
    expect(assets.getAsset).toHaveBeenCalledWith(11)
    expect(state.drawer.value).toBe(true)
    expect(state.activeTab.value).toBe('basic')
    expect(state.detail.value?.asset.ip).toBe('192.168.110.10')
    expect(state.detailLoading.value).toBe(false)
  })

  it('shows the server reason when the detail cannot be read', async () => {
    vi.mocked(assets.getAsset).mockRejectedValue(new Error('资产不存在'))
    const state = await mount()
    await state.open(asset())
    expect(state.error.value).toBe('资产不存在')
    expect(state.detail.value).toBeNull()
    expect(state.detailLoading.value).toBe(false)
  })

  it('keeps a failed asset load in the page state', async () => {
    vi.mocked(assets.listAssets).mockRejectedValue(new Error('资产服务不可用'))
    const state = await mount()
    expect(state.error.value).toBe('资产服务不可用')
    expect(state.loading.value).toBe(false)
  })

  it('builds the relation graph from the asset, its data assets, IOCs and incidents', async () => {
    vi.mocked(assets.getAsset).mockResolvedValue(assetDetail({
      data_assets: [{ id: 3, name: '客户库', sensitivity: 'High' } as never],
      iocs: [{ id: 4, value: '1.2.3.4' } as never],
      incidents: [{ id: 6, title: '可疑外联', risk_level: 'High' } as never],
    }))
    const state = await mount()
    await state.open(asset())
    expect(state.graphNodes.value.map((node) => node.id)).toEqual(['asset:11', 'data:3', 'ioc:4', 'incident:6'])
    expect(state.graphEdges.value.map((edge) => edge.label)).toEqual(['data', 'ioc', 'incident'])
    expect(state.graphEdges.value.every((edge) => edge.source === 'asset:11')).toBe(true)
  })

  it('reports no relation graph without a detail', async () => {
    const state = await mount()
    expect(state.graphNodes.value).toEqual([])
    expect(state.graphEdges.value).toEqual([])
  })
})

describe('asset centre scan console', () => {
  it('summarises the scan result from the alive-host count or the host list', async () => {
    const state = await mount()
    state.scanResult.value = task({ result: { assets: 4, alive_hosts: 3 } })
    expect(state.scanSummary.value).toEqual({ assets: 4, hosts: 3, engine: '' })
    state.scanResult.value = task({ result: { assets: 4, hosts: ['10.0.0.1', '10.0.0.2'] } })
    expect(state.scanSummary.value.hosts).toBe(2)
    state.scanResult.value = null
    expect(state.scanSummary.value).toEqual({ assets: 0, hosts: 0, engine: '' })
  })

  it('refuses to scan without a target and without a probe', async () => {
    const state = await mount()
    await state.runScan()
    expect(ElMessage.warning).toHaveBeenCalledWith('请填写扫描目标')
    expect(scan.startScan).not.toHaveBeenCalled()

    state.scanTarget.value = '192.168.110.0/24'
    state.scanSource.value = 'probe'
    await state.runScan()
    expect(ElMessage.warning).toHaveBeenCalledWith('请选择执行扫描的探针')
    expect(scan.startScan).not.toHaveBeenCalled()
  })

  it('dispatches a platform scan, polls to the terminal status and reports the counts', async () => {
    vi.useFakeTimers()
    vi.mocked(scan.getScan)
      .mockResolvedValueOnce(task({ status: 'Running', progress: 40, current_stage: 'nmap' }))
      .mockResolvedValue(task({ status: 'Success', result: { alive_hosts: 3, assets: 4, engine: 'nmap' } }))
    const state = await mount()
    state.scanTarget.value = ' 192.168.110.0/24 '
    state.scanPorts.value = '22, 80, 70000'
    state.scanNuclei.value = true
    state.scanNucleiTags.value = 'tech'
    vi.mocked(assets.listAssets).mockClear()

    await runScan(state)

    expect(scan.startScan).toHaveBeenCalledWith({
      target: '192.168.110.0/24',
      discovery: true,
      top_ports: 200,
      ports: [22, 80],
      probe_id: undefined,
      nuclei: true,
      nuclei_tags: 'tech',
    })
    expect(state.scanProgress.value).toBe(100)
    expect(state.scanStage.value).toBe('done')
    expect(state.scanResult.value?.status).toBe('Success')
    expect(ElMessage.success).toHaveBeenCalledWith('扫描完成：3 台存活主机，4 个服务资产')
    expect(assets.listAssets).toHaveBeenCalledTimes(1)
    expect(state.scanning.value).toBe(false)
  })

  it('runs a probe scan and reports the service assets it found', async () => {
    vi.useFakeTimers()
    vi.mocked(scan.getScan).mockResolvedValue(task({
      status: 'Partial', location: 'probe', current_stage: 'python-tcp',
      result: { assets: 4 }, scanned_assets: [],
    }))
    const state = await mount()
    state.scanSource.value = 'probe'
    state.scanProbeId.value = 2
    state.scanTarget.value = '10.0.0.0/24'

    await runScan(state)

    expect(scan.startScan).toHaveBeenCalledWith({
      target: '10.0.0.0/24',
      discovery: true,
      top_ports: 200,
      ports: [],
      probe_id: 2,
      nuclei: false,
      nuclei_tags: '',
    })
    expect(ElMessage.success).toHaveBeenCalledWith('探针扫描完成：发现 4 个服务资产')
    expect(state.scanStage.value).toBe('服务检测')
  })

  it('surfaces a failed scan', async () => {
    vi.useFakeTimers()
    vi.mocked(scan.getScan).mockResolvedValue(task({ status: 'Failed', error: 'nmap 不可用' }))
    const state = await mount()
    state.scanTarget.value = '10.0.0.1'

    await runScan(state)

    expect(ElMessage.error).toHaveBeenCalledWith('nmap 不可用')
    expect(state.scanning.value).toBe(false)
  })

  it('reports a timeout when the task never reaches a terminal status', async () => {
    vi.useFakeTimers()
    vi.mocked(scan.getScan).mockResolvedValue(task({ status: 'Running', progress: 10 }))
    const state = await mount()
    state.scanTarget.value = '10.0.0.1'
    vi.mocked(assets.listAssets).mockClear()

    await runScan(state, 250)

    expect(ElMessage.error).toHaveBeenCalledWith('扫描超时，请稍后在任务中心查看结果')
    expect(assets.listAssets).not.toHaveBeenCalled()
    expect(state.scanning.value).toBe(false)
  })
})
