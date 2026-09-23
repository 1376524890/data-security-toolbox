import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ElMessage } from 'element-plus'
import { listDataAssets, getDataAsset } from '../api/dataAssets'
import { collectProbeDataAssets } from '../api/probes'
import { getTask } from '../api/tasks'
import { useDataAssetList } from '../modules/data-security/composables/useDataAssetList'
import { useDataAssetCollection } from '../modules/data-security/composables/useDataAssetCollection'
import type { Task } from '../types/task'

vi.mock('../api/dataAssets', () => ({ listDataAssets: vi.fn(), getDataAsset: vi.fn() }))
vi.mock('../api/probes', () => ({ listProbes: vi.fn(), collectProbeDataAssets: vi.fn() }))
vi.mock('../api/tasks', () => ({ getTask: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessage: { warning: vi.fn(), success: vi.fn(), error: vi.fn() } }))

beforeEach(() => { vi.clearAllMocks(); vi.useFakeTimers() })
afterEach(() => vi.useRealTimers())

const asset = { id: 1, name: 'observed.csv', asset_type: 'file', sensitivity: 'High',
  source: 'probe:1', columns: [], created_at: '' }
const task = (status: string, result = {}): Task => ({ id: 7, kind: 'data_asset_scan', status,
  progress: 80, current_stage: '采集中', log: '', payload: {}, result, error: '', created_at: '' })

describe('asset read state', () => {
  it('keeps server totals and field/hit units when filtering and opening details', async () => {
    vi.mocked(listDataAssets).mockResolvedValue({ items: [asset], total: 300, page: 1, page_size: 50 })
    vi.mocked(getDataAsset).mockResolvedValue({ data_asset: asset, findings: [],
      pii_summary: { email: 1 }, pii_summary_detail: { email: { fields: 1, sample_hits: 100 } } })
    const state = useDataAssetList()
    state.filters.probe_id = '12'
    await state.load()
    expect(listDataAssets).toHaveBeenCalledWith(expect.objectContaining({ probe_id: 12, page: 1 }))
    expect(state.total.value).toBe(300)
    await state.open(asset)
    expect(state.piiData.value).toEqual([{ name: 'email', fields: 1, sample_hits: 100 }])
    expect(state.drawer.value).toBe(true)
  })
})

describe('asset collection state', () => {
  it('passes scope settings and refreshes once after a partial result without reporting full success', async () => {
    vi.mocked(collectProbeDataAssets).mockResolvedValue(task('Pending'))
    vi.mocked(getTask).mockResolvedValue(task('Partial', { assets: 8, coverage: { termination_reason: 'row_budget' } }))
    const refresh = vi.fn()
    const state = useDataAssetCollection(refresh)
    Object.assign(state.collectForm, { probe_id: 12, pathsText: '/srv/data, /etc', max_files: 15 })
    state.openCollect()
    const pending = state.submitCollect()
    await vi.advanceTimersByTimeAsync(3000)
    await pending
    expect(collectProbeDataAssets).toHaveBeenCalledWith(12, expect.objectContaining({ paths: ['/srv/data', '/etc'], max_files: 15 }))
    // The dialog reports the same translated reason the task centre shows,
    // not the scanner's internal code.
    expect(ElMessage.warning).toHaveBeenCalledWith(expect.stringContaining('达到行数上限'))
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(refresh).toHaveBeenCalledOnce()
    expect(state.collectDialog.value).toBe(false)
    expect(state.collecting.value).toBe(false)
  })

  it('does not refresh or announce success when collection is cancelled', async () => {
    vi.mocked(collectProbeDataAssets).mockResolvedValue(task('Pending'))
    vi.mocked(getTask).mockResolvedValue(task('Cancelled'))
    const refresh = vi.fn()
    const state = useDataAssetCollection(refresh)
    Object.assign(state.collectForm, { probe_id: 12, pathsText: '/srv/data' })
    const pending = state.submitCollect()
    await vi.advanceTimersByTimeAsync(3000)
    await pending
    expect(refresh).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('采集任务已取消')
    expect(state.collecting.value).toBe(false)
  })
})
