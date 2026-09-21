import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useDataAssetJobs } from '../modules/data-security/composables/useDataAssetJobs'
import type { Probe } from '../api/probes'
import type { ScanProfile } from '../api/scanProfiles'
import type { Task } from '../types/task'
import * as probes from '../api/probes'
import * as scanProfiles from '../api/scanProfiles'
import * as tasks from '../api/tasks'
import * as catalog from '../api/dataCatalog'
vi.mock('../api/dataCatalog', () => ({ listAssetInstances: vi.fn() }))

vi.mock('../api/probes', () => ({ listProbes: vi.fn() }))
vi.mock('../api/scanProfiles', () => ({ listScanProfiles: vi.fn(), queueDataAssetJob: vi.fn() }))
vi.mock('../api/tasks', () => ({ listTasks: vi.fn(), stopTask: vi.fn(), deleteTask: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const probe = { id: 12, name: 'test123', hostname: 'host', ip_address: '192.168.191.130',
  status: 'online', metadata: {}, created_at: '' } as Probe
const profile = { id: 3, name: '默认采集配置', version: 2, enabled: true,
  include_paths: ['/srv/data'] } as unknown as ScanProfile
const job = (id: number, status: string, result: Record<string, unknown> = {}): Task => ({
  id, kind: 'data_asset_scan', status, progress: 40, current_stage: '采集中', log: '',
  payload: {}, result, error: '', created_at: '',
})

let state: ReturnType<typeof useDataAssetJobs>
let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

// The composable owns the polling timer, so the harness mounts a real component
// instance: onMounted must run for the interval to exist at all.
const mountJobs = async () => {
  const Harness = defineComponent({
    setup() {
      state = useDataAssetJobs()
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
  vi.useFakeTimers()
  vi.mocked(probes.listProbes).mockResolvedValue({ items: [probe], total: 1, page: 1, page_size: 200 })
  vi.mocked(scanProfiles.listScanProfiles).mockResolvedValue({ items: [profile], total: 1, page: 1, page_size: 200 })
  vi.mocked(tasks.listTasks).mockResolvedValue({ items: [job(7, 'Running')], total: 1, page: 1, page_size: 50 })
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
  vi.useRealTimers()
})

describe('data asset job state', () => {
  it('loads the probe and profile choices plus the data-asset jobs', async () => {
    await mountJobs()
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(scanProfiles.listScanProfiles).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(tasks.listTasks).toHaveBeenCalledWith({ kind: 'data_asset_scan', page: 1, page_size: 50 })
    expect(state.jobs.value.map((item) => item.id)).toEqual([7])
    expect(state.probeId.value).toBe(probe.id)
    expect(state.profileId.value).toBe(profile.id)
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('keeps a failed listing in the page state instead of throwing', async () => {
    vi.mocked(probes.listProbes).mockRejectedValue(new Error('后端不可用'))
    await mountJobs()
    expect(state.error.value).toBe('后端不可用')
    expect(state.loading.value).toBe(false)
    expect(tasks.listTasks).not.toHaveBeenCalled()
  })

  it('counts running, finished and partial jobs for the stat cards', async () => {
    vi.mocked(tasks.listTasks).mockResolvedValue({ items: [job(1, 'Running'), job(2, 'Pending'),
      job(3, 'Success'), job(4, 'Partial'), job(5, 'Partial'), job(6, 'Failed')], total: 6, page: 1, page_size: 50 })
    await mountJobs()
    expect(state.running.value).toBe(2)
    expect(state.finished.value).toBe(1)
    expect(state.partial.value).toBe(2)
  })

  it('words a finished walk with a short file sample differently from an unwalked scope', async () => {
    await mountJobs()
    expect(state.coverageNote(job(1, 'Success', {}))).toBe('')
    expect(state.coverageNote(job(2, 'Partial', { coverage: {
      complete_scope: false, enumeration_complete: true, content_complete: false,
      termination_reason: 'row_budget' } })))
      .toBe('· 目录已完整枚举，部分文件内容按上限截断')
    expect(state.coverageNote(job(3, 'Partial', { coverage: {
      complete_scope: false, enumeration_complete: false, content_complete: false,
      termination_reason: 'file_budget' } })))
      .toBe('· 范围未完整覆盖')
    // An older report carries neither flag: it keeps the cautious wording.
    expect(state.coverageNote(job(4, 'Partial', { coverage: { complete_scope: false } })))
      .toBe('· 范围未完整覆盖')
  })

  it('lets explicit paths win over the profile and refreshes the list after dispatch', async () => {
    await mountJobs()
    vi.mocked(tasks.listTasks).mockClear()
    vi.mocked(scanProfiles.queueDataAssetJob).mockResolvedValue({ id: 77, status: 'Pending' })
    state.pathsText.value = '  /srv/data \n\n/srv/etc  '

    await state.dispatch()
    expect(scanProfiles.queueDataAssetJob).toHaveBeenCalledWith(12,
      { paths: ['/srv/data', '/srv/etc'], profile_id: 3 })
    expect(ElMessage.success).toHaveBeenCalledWith('已下发任务 #77')
    expect(tasks.listTasks).toHaveBeenCalledOnce()
    expect(state.dispatching.value).toBe(false)
  })

  it('sends only the profile when no path is typed and refuses to dispatch without a probe', async () => {
    await mountJobs()
    vi.mocked(scanProfiles.queueDataAssetJob).mockResolvedValue({ id: 78, status: 'Pending' })
    state.pathsText.value = '   '

    await state.dispatch()
    expect(scanProfiles.queueDataAssetJob).toHaveBeenCalledWith(12, { profile_id: 3 })

    state.probeId.value = null
    await state.dispatch()
    expect(scanProfiles.queueDataAssetJob).toHaveBeenCalledOnce()
  })

  it('reports a failed dispatch without touching the job list', async () => {
    await mountJobs()
    vi.mocked(tasks.listTasks).mockClear()
    vi.mocked(scanProfiles.queueDataAssetJob).mockRejectedValue(new Error('探针离线'))
    state.pathsText.value = '/srv/data'

    await state.dispatch()
    expect(ElMessage.error).toHaveBeenCalledWith('探针离线')
    expect(tasks.listTasks).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
  })

  it('cancels and removes jobs through the task API and reloads the list', async () => {
    await mountJobs()
    vi.mocked(tasks.stopTask).mockResolvedValue(job(7, 'Cancelled'))
    vi.mocked(tasks.deleteTask).mockResolvedValue(undefined)
    vi.mocked(tasks.listTasks).mockClear()

    await state.cancel(job(7, 'Running'))
    expect(tasks.stopTask).toHaveBeenCalledWith(7)
    expect(ElMessage.success).toHaveBeenCalledWith(expect.stringContaining('任务 #7 已取消'))

    await state.remove(job(7, 'Success'))
    expect(tasks.deleteTask).toHaveBeenCalledWith(7)
    expect(ElMessage.success).toHaveBeenCalledWith('已从列表移除（探针记录保留）')
    expect(tasks.listTasks).toHaveBeenCalledTimes(2)
  })

  it('polls the job list every 5s and stops when auto refresh is switched off', async () => {
    await mountJobs()
    vi.mocked(tasks.listTasks).mockClear()

    await vi.advanceTimersByTimeAsync(5000)
    expect(tasks.listTasks).toHaveBeenCalledTimes(1)

    state.autoRefresh.value = false
    await vi.advanceTimersByTimeAsync(15000)
    expect(tasks.listTasks).toHaveBeenCalledTimes(1)

    state.autoRefresh.value = true
    await vi.advanceTimersByTimeAsync(5000)
    expect(tasks.listTasks).toHaveBeenCalledTimes(2)
  })

  it('stops polling when the page unmounts', async () => {
    await mountJobs()
    app?.unmount()
    vi.mocked(tasks.listTasks).mockClear()

    await vi.advanceTimersByTimeAsync(15000)
    expect(tasks.listTasks).not.toHaveBeenCalled()
  })
})


describe('task asset drawer', () => {
  it('queries the selected task and paginates within that task', async () => {
    vi.mocked(catalog.listAssetInstances).mockResolvedValue({ items: [], total: 72, page: 1, page_size: 50, association: 'recorded_membership' })
    await mountJobs()
    await state.openAssets(job(44, 'Partial'))
    expect(catalog.listAssetInstances).toHaveBeenLastCalledWith({ task_id: 44, page: 1, page_size: 50 })
    expect(state.assetTotal.value).toBe(72)
    await state.loadAssets(2)
    expect(catalog.listAssetInstances).toHaveBeenLastCalledWith({ task_id: 44, page: 2, page_size: 50 })
  })

  it('ignores a response after the drawer closes', async () => {
    let resolve!: (value: any) => void
    vi.mocked(catalog.listAssetInstances).mockReturnValue(new Promise((done) => { resolve = done }))
    await mountJobs()
    const pending = state.openAssets(job(44, 'Success'))
    state.closeAssets()
    resolve({ items: [{ id: 10 }], total: 1 })
    await pending
    expect(state.assetJob.value).toBeNull()
    expect(state.assetRows.value).toEqual([])
  })
})
