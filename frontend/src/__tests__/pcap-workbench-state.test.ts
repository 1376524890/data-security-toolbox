import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import ElementPlus, { ElMessage } from 'element-plus'
import { usePcapWorkbench } from '../modules/network/pcap/composables/usePcapWorkbench'
import type { PcapRecord } from '../types/pcap'
import * as pcaps from '../api/pcaps'
import * as tasks from '../api/tasks'

vi.mock('../api/tasks', () => ({ getTask: vi.fn() }))
vi.mock('../api/pcaps', () => ({
  listPcaps: vi.fn(), getPcap: vi.fn(), uploadPcap: vi.fn(), analyzePcap: vi.fn(),
  getPcapFlows: vi.fn(), getPcapPackets: vi.fn(), getPcapAlerts: vi.fn(),
  getPcapDns: vi.fn(), getPcapHttp: vi.fn(), getPcapTls: vi.fn(), getPcapFiles: vi.fn(),
  getTraffic: vi.fn(), getPcapProtocols: vi.fn(), getPcapAnomalies: vi.fn(),
  getPcapPacketDetail: vi.fn(), getPcapStream: vi.fn(), getPcapFilePreview: vi.fn(),
  getPcapFileDownloadUrl: vi.fn(() => '/download'),
}))

const capture: PcapRecord = {
  id: 651, filename: 'existing.pcap', size: 151424, status: 'analyzed',
  packet_count: 284, total_packet_count: 284, indexed_packet_count: 284, duration: 1,
  sha256: '', capture_start: '', capture_end: '', protocol_summary: {}, created_at: '',
}
const other: PcapRecord = { ...capture, id: 652, filename: 'second.pcap' }

let state: ReturnType<typeof usePcapWorkbench>
let app: App
let host: HTMLElement

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountWorkbench = async () => {
  const Harness = defineComponent({
    setup() {
      state = usePcapWorkbench()
      return () => null
    },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(Harness)
  app.use(ElementPlus)
  app.mount(host)
  await flushing()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(pcaps.listPcaps).mockResolvedValue({ items: [capture], total: 1, page: 1, page_size: 50 })
  vi.mocked(pcaps.getPcap).mockResolvedValue(capture)
  vi.mocked(pcaps.getPcapFlows).mockResolvedValue({ items: [], total: 300, page: 1, page_size: 50 })
  vi.mocked(pcaps.getPcapPackets).mockResolvedValue({ items: [], total: 284, page: 1, page_size: 100 })
  for (const fn of [pcaps.getPcapAlerts, pcaps.getPcapDns, pcaps.getPcapHttp, pcaps.getPcapTls, pcaps.getPcapFiles]) {
    vi.mocked(fn).mockResolvedValue({ items: [] })
  }
  vi.mocked(pcaps.getPcapProtocols).mockResolvedValue([])
  vi.mocked(pcaps.getPcapAnomalies).mockResolvedValue([])
  vi.mocked(pcaps.getTraffic).mockResolvedValue({ trend: [], top_n: [], protocols: {}, hosts: [], anomalies: [] })
})

afterEach(() => {
  app.unmount()
  host.remove()
  ElMessage.closeAll()
})

describe('PCAP workbench state', () => {
  it('loads the capture list and keeps a failed listing in the page state', async () => {
    await mountWorkbench()
    expect(pcaps.listPcaps).toHaveBeenCalledWith({ search: '', status: '', page: 1, page_size: 50 })
    expect(state.items.value).toEqual([capture])
    expect(state.total.value).toBe(1)
    expect(state.loading.value).toBe(false)

    vi.mocked(pcaps.listPcaps).mockRejectedValue(new Error('后端不可用'))
    await state.load()
    expect(state.error.value).toBe('后端不可用')
    expect(state.loading.value).toBe(false)
  })

  it('keeps the newest capture when two opens race', async () => {
    await mountWorkbench()
    let resolveFirst: (value: PcapRecord) => void = () => {}
    vi.mocked(pcaps.getPcap).mockImplementation((id) => id === capture.id
      ? new Promise<PcapRecord>((resolve) => { resolveFirst = resolve })
      : Promise.resolve(other))

    const first = state.openPcap(capture)
    const second = state.openPcap(other)
    await flushing()
    await second
    expect(state.selected.value?.id).toBe(other.id)

    resolveFirst(capture)
    await first
    await flushing()
    expect(state.selected.value?.id).toBe(other.id)
    expect(state.selected.value?.filename).toBe('second.pcap')
  })

  it('opens the existing capture when an upload is deduplicated', async () => {
    await mountWorkbench()
    state.filters.search = 'renamed'
    state.filters.status = 'pending'
    vi.mocked(pcaps.uploadPcap).mockResolvedValue({ id: capture.id, task_id: null, filename: capture.filename, size: capture.size, duplicate: true })

    await state.handleUpload(new File(['capture'], 'renamed.pcap'))
    expect(pcaps.uploadPcap).toHaveBeenCalledOnce()
    expect(state.selected.value?.id).toBe(capture.id)
    expect(state.filters.search).toBe('')
    expect(state.filters.status).toBe('')
    expect(document.body.textContent).toContain('文件已存在，已定位到记录 #651')
  })

  it('rejects an empty capture without touching the API', async () => {
    await mountWorkbench()
    await state.handleUpload(new File([], 'empty.pcap'))
    expect(pcaps.uploadPcap).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('抓包文件为空')
    expect(state.uploadProgress.value).toBeNull()
  })

  it('paginates packets with the current query and drops a stale page', async () => {
    await mountWorkbench()
    await state.openPcap(capture)
    vi.mocked(pcaps.getPcapPackets).mockClear()

    state.packetQuery.page = 2
    state.packetQuery.search = '10.0.0.1'
    await state.loadPackets()
    expect(pcaps.getPcapPackets).toHaveBeenLastCalledWith(capture.id, 2, 100, '10.0.0.1')

    let resolveStale: (value: { items: any[]; total: number; page: number; page_size: number }) => void = () => {}
    vi.mocked(pcaps.getPcapPackets).mockImplementationOnce(() => new Promise((resolve) => { resolveStale = resolve }))
    const stale = state.loadPackets()
    await state.loadPackets()
    resolveStale({ items: [{ id: 99 }], total: 1, page: 1, page_size: 100 })
    await stale
    await flushing()
    expect(state.packets.value).toEqual([])
    expect(state.packetTotal.value).toBe(284)
  })

  it('follows a TCP stream into the dialog and previews retained file bytes', async () => {
    await mountWorkbench()
    await state.openPcap(capture)
    vi.mocked(pcaps.getPcapStream).mockResolvedValue({
      stream: '1', nodes: [{ node: 0, ip: '10.0.0.1', port: 51000 }],
      directions: [{ direction: 'client', ascii: 'GET /', hex: '47 45 54' }],
    })
    await state.followStream(1)
    expect(state.streamData.value?.directions[0].ascii).toBe('GET /')
    expect(state.streamDialog.value).toBe(true)

    const file = { id: 'a'.repeat(64), filename: 'report.txt', size: 5, mime_type: 'text/plain', binary_available: false }
    await state.showFile(file)
    expect(pcaps.getPcapFilePreview).not.toHaveBeenCalled()
    expect(state.fileDialog.value).toBe(false)

    const retained = { ...file, binary_available: true }
    vi.mocked(pcaps.getPcapFilePreview).mockResolvedValue({ ...retained, offset: 16384, length: 5, text: 'world', hex: '776f726c64', encoding: 'utf-8', binary: false, has_more: false })
    await state.showFile(retained, 16384)
    expect(pcaps.getPcapFilePreview).toHaveBeenLastCalledWith(capture.id, file.id, 16384)
    expect(state.filePreview.value?.text).toBe('world')
  })

  it('drops a file preview that answers after the dialog was closed', async () => {
    await mountWorkbench()
    await state.openPcap(capture)
    const file = { id: 'b'.repeat(64), filename: 'late.txt', size: 5, mime_type: 'text/plain', binary_available: true }
    let resolvePreview: (value: any) => void = () => {}
    vi.mocked(pcaps.getPcapFilePreview).mockImplementationOnce(() => new Promise((resolve) => { resolvePreview = resolve }))

    const pending = state.showFile(file)
    state.closeFileDialog()
    resolvePreview({ ...file, offset: 0, length: 5, text: 'late', hex: '6c6174', encoding: 'utf-8', binary: false, has_more: false })
    await pending
    await flushing()
    expect(state.filePreview.value).toBeNull()
  })

  it('polls the analysis task and reopens the capture once it succeeds', async () => {
    await mountWorkbench()
    await state.openPcap(capture)
    vi.mocked(pcaps.analyzePcap).mockResolvedValue({ id: 77 })
    vi.mocked(tasks.getTask)
      .mockResolvedValueOnce({ status: 'Running', current_stage: '解析', progress: 40, error: '' } as any)
      .mockResolvedValueOnce({ status: 'Success', current_stage: '完成', progress: 100, error: '' } as any)
    vi.mocked(pcaps.getPcap).mockClear()

    vi.useFakeTimers()
    try {
      await state.runAnalyze(capture)
      await flushing()
      expect(state.analyzingId.value).toBe(capture.id)
      expect(state.analysisStage.value).toBe('解析 40%')

      await vi.advanceTimersByTimeAsync(3000)
      await flushing()
      expect(state.analyzingId.value).toBeNull()
      expect(pcaps.getPcap).toHaveBeenCalledWith(capture.id)
    } finally {
      vi.useRealTimers()
    }
  })

  it('returns to the list and reloads it when going back', async () => {
    await mountWorkbench()
    await state.openPcap(capture)
    vi.mocked(pcaps.listPcaps).mockClear()
    state.activeTab.value = 'files'
    state.back()
    await flushing()
    expect(state.selected.value).toBeNull()
    expect(pcaps.listPcaps).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1 }))
  })
})
