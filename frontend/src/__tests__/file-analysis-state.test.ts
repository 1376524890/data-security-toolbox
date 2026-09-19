import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useFileAnalysis, type FileDetail, type FileRecord } from '../modules/data-security/composables/useFileAnalysis'
import * as api from '../api/client'

vi.mock('../api/client', () => ({
  apiGet: vi.fn(), apiPost: vi.fn(), apiPatch: vi.fn(), apiUpload: vi.fn(), downloadUrl: vi.fn(),
}))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const mocked = api as unknown as { apiGet: Mock; apiPost: Mock; apiUpload: Mock }

const record = (overrides: Partial<FileRecord> = {}): FileRecord => ({
  id: 1, name: 'a.pdf', path: '/srv/a.pdf', size: 1024, sha256: 'a'.repeat(64),
  file_type: 'pdf', metadata_json: {}, risk_level: 'Low', created_at: '2026-09-19T10:00:00',
  ...overrides,
})

const detail = (overrides: Partial<FileDetail> = {}): FileDetail => ({
  file: record(), findings: [], data_assets: [], ...overrides,
})

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
  mocked.apiGet.mockImplementation(async (path: string) => {
    if (path === '/files') return { items: [record()], total: 61 }
    if (path === '/files/1') return detail()
    return {}
  })
  mocked.apiPost.mockResolvedValue({})
  mocked.apiUpload.mockResolvedValue({})
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('file analysis workbench state', () => {
  it('loads the first page with the active filters and keeps the server total', async () => {
    const state = await mount(() => useFileAnalysis())
    expect(mocked.apiGet).toHaveBeenCalledWith('/files', {
      search: '', file_type: '', risk_level: '', page: 1, page_size: 50,
    })
    expect(state.rows.value.map((row) => row.id)).toEqual([1])
    expect(state.total.value).toBe(61)
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('returns to the first page when the filter bar resets', async () => {
    const state = await mount(() => useFileAnalysis())
    state.filters.search = 'report'
    state.filters.page = 4
    mocked.apiGet.mockClear()
    state.reset()
    await flushing()
    expect(state.filters.page).toBe(1)
    expect(mocked.apiGet).toHaveBeenCalledWith('/files', {
      search: 'report', file_type: '', risk_level: '', page: 1, page_size: 50,
    })
  })

  it('uploads a file through the client and reloads the list', async () => {
    const state = await mount(() => useFileAnalysis())
    const file = new File(['x'], 'a.pdf')
    await state.handleUpload(file)
    expect(mocked.apiUpload).toHaveBeenCalledWith('/files/upload', file)
    expect(ElMessage.success).toHaveBeenCalledWith('文件已上传')
    expect(state.uploading.value).toBe(false)
    expect(mocked.apiGet).toHaveBeenCalledTimes(2)
  })

  it('opens the drawer only once the detail request succeeds', async () => {
    const state = await mount(() => useFileAnalysis())
    await state.open(record())
    expect(mocked.apiGet).toHaveBeenCalledWith('/files/1')
    expect(state.drawer.value).toBe(true)
    expect(state.detail.value?.file.id).toBe(1)

    mocked.apiGet.mockRejectedValue(new Error('文件已被清理'))
    await state.open(record({ id: 2 }))
    expect(ElMessage.error).toHaveBeenCalledWith('文件已被清理')
  })

  it('exposes the hidden-info block the drawer renders', async () => {
    mocked.apiGet.mockImplementation(async (path: string) => (path === '/files/1'
      ? detail({ file: record({ metadata_json: { hidden_info: { hidden: true, findings: [] } } }) })
      : { items: [], total: 0 }))
    const state = await mount(() => useFileAnalysis())
    await state.open(record())
    expect(state.hiddenInfo.value?.hidden).toBe(true)
  })

  it('re-runs the analysis and reports a refusal', async () => {
    const state = await mount(() => useFileAnalysis())
    await state.reanalyze(record())
    expect(mocked.apiPost).toHaveBeenCalledWith('/files/1/analyze')
    expect(ElMessage.success).toHaveBeenCalledWith('已触发重新分析')

    mocked.apiPost.mockRejectedValue(new Error('分析队列已满'))
    await state.reanalyze(record())
    expect(ElMessage.error).toHaveBeenCalledWith('分析队列已满')
  })

  it('refreshes an open drawer every 4s and stops when the page unmounts', async () => {
    vi.useFakeTimers()
    const state = await mount(() => useFileAnalysis())
    await state.open(record())
    mocked.apiGet.mockClear()

    await vi.advanceTimersByTimeAsync(4000)
    expect(mocked.apiGet).toHaveBeenCalledWith('/files/1')
    expect(state.detail.value?.file.id).toBe(1)

    mocked.apiGet.mockClear()
    app?.unmount()
    app = undefined
    await vi.advanceTimersByTimeAsync(12000)
    expect(mocked.apiGet).not.toHaveBeenCalled()
    vi.useRealTimers()
  })

  it('does not poll while the drawer is closed', async () => {
    vi.useFakeTimers()
    await mount(() => useFileAnalysis())
    mocked.apiGet.mockClear()
    await vi.advanceTimersByTimeAsync(12000)
    expect(mocked.apiGet).not.toHaveBeenCalled()
    vi.useRealTimers()
  })

  it('keeps a failed load in the page state', async () => {
    mocked.apiGet.mockRejectedValue(new Error('文件服务不可用'))
    const state = await mount(() => useFileAnalysis())
    expect(state.error.value).toBe('文件服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.rows.value).toEqual([])
  })
})
