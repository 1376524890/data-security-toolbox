/**
 * Shared-file source state.
 *
 * Two contracts matter here: the password is write-only (a stored one is never
 * read back into the page and an untouched field must not be submitted), and a
 * collection is only ever reported through the task the server created.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useFileSources } from '../modules/collection/composables/useFileSources'
import type { FileSource } from '../api/fileSources'
import * as api from '../api/fileSources'

vi.mock('../api/fileSources', () => ({
  listFileSources: vi.fn(), saveFileSource: vi.fn(), runFileSource: vi.fn(), deleteFileSource: vi.fn(),
}))
vi.mock('element-plus', () => ({
  ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
  ElMessageBox: { confirm: vi.fn() },
}))

const source = (overrides: Partial<FileSource> = {}): FileSource => ({
  id: 4, name: 'kali-ftp', protocol: 'ftp', host: '192.168.191.130', port: 21,
  username: 'kali', root_path: '/srv/ftp', host_key_sha256: '', enabled: true,
  password_set: true, interval_minutes: 0, next_scan_at: null,
  limits: { max_files: 200, max_depth: 3, max_bytes: 67108864, max_file_bytes: 8388608, max_seconds: 120 },
  last_status: 'Success', last_error: '', last_scan_at: '2026-09-20T07:00:00Z',
  ...overrides,
})

const page = (items: FileSource[], total = items.length, number = 1) => ({
  items, total, page: number, page_size: 50,
})

let state: ReturnType<typeof useFileSources>
let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let index = 0; index < 4; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountState = async () => {
  const Harness = defineComponent({
    setup() {
      state = useFileSources()
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
  vi.mocked(api.listFileSources).mockResolvedValue(page([source()]))
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
  vi.useRealTimers()
})

describe('shared file sources', () => {
  it('loads the first page and keeps the server totals', async () => {
    await mountState()
    expect(api.listFileSources).toHaveBeenCalledWith(1)
    expect(state.rows.value.map((row) => row.name)).toEqual(['kali-ftp'])
    expect(state.total.value).toBe(1)
    expect(state.error.value).toBe('')
    expect(state.loading.value).toBe(false)
  })

  it('never reads the stored password back and keeps it when the field is empty', async () => {
    vi.mocked(api.saveFileSource).mockResolvedValue(source({ name: 'renamed' }))
    await mountState()
    state.edit(source())
    expect(state.form.name).toBe('kali-ftp')
    expect(state.form.password).toBe('')
    state.form.interval_minutes = 60
    state.form.root_path = '/srv/ftp/pub'
    await state.save()
    const [id, payload] = vi.mocked(api.saveFileSource).mock.calls[0]
    expect(id).toBe(4)
    expect(payload).not.toHaveProperty('password')
    expect(payload.interval_minutes).toBe(60)
    // The shared directory may move; only protocol/host/port require a new source.
    expect(payload.root_path).toBe('/srv/ftp/pub')
    expect(state.open.value).toBe(false)
  })

  it('removes a source only after the operator confirms', async () => {
    vi.mocked(api.deleteFileSource).mockResolvedValue({ id: 4 })
    await mountState()
    vi.mocked(ElMessageBox.confirm).mockRejectedValueOnce(new Error('cancel'))
    await state.remove(source())
    expect(api.deleteFileSource).not.toHaveBeenCalled()

    vi.mocked(ElMessageBox.confirm).mockResolvedValue('confirm' as never)
    await state.remove(source())
    expect(api.deleteFileSource).toHaveBeenCalledWith(4)
    expect(ElMessage.success).toHaveBeenCalled()
    expect(api.listFileSources).toHaveBeenCalledTimes(2)
    expect(state.busy.value).toBeNull()
  })

  it('keeps the row when the server refuses to remove a busy source', async () => {
    vi.mocked(ElMessageBox.confirm).mockResolvedValue('confirm' as never)
    vi.mocked(api.deleteFileSource).mockRejectedValue(new Error('source_busy'))
    await mountState()
    await state.remove(source())
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
    expect(api.listFileSources).toHaveBeenCalledTimes(1)
    expect(state.busy.value).toBeNull()
  })

  it('sends a replaced password once and clears it from the form', async () => {
    vi.mocked(api.saveFileSource).mockResolvedValue(source())
    await mountState()
    state.edit(source())
    state.form.password = 'new-secret'
    await state.save()
    expect(vi.mocked(api.saveFileSource).mock.calls[0][1]).toMatchObject({ password: 'new-secret' })
    expect(state.form.password).toBe('')
    expect(ElMessage.error).not.toHaveBeenCalled()
  })

  it('creates a collection task from the row and reloads the list', async () => {
    vi.mocked(api.runFileSource).mockResolvedValue({ id: 77 })
    await mountState()
    state.run(source(), 'scan')
    await flushing()
    expect(api.runFileSource).toHaveBeenCalledWith(4, 'scan')
    expect(String(vi.mocked(ElMessage.success).mock.calls[0][0])).toContain('#77')
    expect(api.listFileSources).toHaveBeenCalledTimes(2)
    expect(state.busy.value).toBeNull()
  })

  it('reports a rejected start and releases the row', async () => {
    vi.mocked(api.runFileSource).mockRejectedValue(new Error('source_busy'))
    await mountState()
    state.run(source(), 'test')
    await flushing()
    expect(ElMessage.error).toHaveBeenCalledTimes(1)
    expect(api.listFileSources).toHaveBeenCalledTimes(1)
    expect(state.busy.value).toBeNull()
  })

  it('reports a failed listing instead of inventing rows', async () => {
    vi.mocked(api.listFileSources).mockRejectedValue(new Error('503 unavailable'))
    await mountState()
    expect(state.error.value).toContain('503')
    expect(state.rows.value).toEqual([])
  })

  it('asks the server for the page the operator selected', async () => {
    vi.mocked(api.listFileSources).mockResolvedValue(page([source({ id: 9 })], 120, 3))
    await mountState()
    state.load(3)
    await flushing()
    expect(api.listFileSources).toHaveBeenLastCalledWith(3)
    expect(state.page.value).toBe(3)
    expect(state.total.value).toBe(120)
  })

  it('stops polling once the page is gone', async () => {
    await mountState()
    expect(api.listFileSources).toHaveBeenCalledTimes(1)
    vi.advanceTimersByTime(10000)
    await flushing()
    expect(api.listFileSources).toHaveBeenCalledTimes(2)
    app?.unmount()
    app = undefined
    vi.advanceTimersByTime(30000)
    await flushing()
    expect(api.listFileSources).toHaveBeenCalledTimes(2)
  })
})
