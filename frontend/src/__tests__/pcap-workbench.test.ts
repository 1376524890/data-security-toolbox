import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import ElementPlus, { ElMessage } from 'element-plus'
import PcapWorkbench from '../modules/network/pcap/PcapWorkbench.vue'
import * as pcaps from '../api/pcaps'

vi.mock('../components/evidence/RawViewer.vue', () => ({ default: { template: '<pre />' } }))
vi.mock('../components/evidence/JsonViewer.vue', () => ({ default: { template: '<pre />' } }))
vi.mock('../api/tasks', () => ({ getTask: vi.fn() }))
vi.mock('../api/pcaps', () => ({
  listPcaps: vi.fn(), getPcap: vi.fn(), uploadPcap: vi.fn(), analyzePcap: vi.fn(),
  getPcapFlows: vi.fn(), getPcapPackets: vi.fn(), getPcapAlerts: vi.fn(),
  getPcapDns: vi.fn(), getPcapHttp: vi.fn(), getPcapTls: vi.fn(), getPcapFiles: vi.fn(),
  getTraffic: vi.fn(), getPcapProtocols: vi.fn(), getPcapAnomalies: vi.fn(),
  getPcapPacketDetail: vi.fn(), getPcapStream: vi.fn(), getPcapFilePreview: vi.fn(),
  getPcapFileDownloadUrl: vi.fn(() => '/download'),
}))

const capture = { id: 651, filename: 'existing.pcap', size: 151424, status: 'analyzed',
  packet_count: 284, total_packet_count: 284, indexed_packet_count: 284, duration: 1,
  sha256: '', capture_start: '', capture_end: '', protocol_summary: {}, created_at: '' }
let app: App
let host: HTMLElement
const flush = async () => {
  await new Promise((resolve) => setTimeout(resolve, 0))
  await nextTick()
  await new Promise((resolve) => setTimeout(resolve, 0))
}

beforeEach(async () => {
  vi.clearAllMocks()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
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
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(PcapWorkbench)
  app.component('Back', { template: '<span />' })
  app.use(ElementPlus)
  app.mount(host)
  await flush()
})

afterEach(() => {
  app.unmount()
  host.remove()
  ElMessage.closeAll()
  vi.unstubAllGlobals()
})

describe('PCAP workbench', () => {
  it('opens the existing capture when a manual upload is deduplicated', async () => {
    vi.mocked(pcaps.uploadPcap).mockResolvedValue({ id: 651, task_id: null, filename: 'existing.pcap', size: 151424, duplicate: true })
    const input = host.querySelector<HTMLInputElement>('input[type=file]')!
    Object.defineProperty(input, 'files', { value: [new File(['capture'], 'renamed.pcap')] })
    input.dispatchEvent(new Event('change', { bubbles: true }))
    await flush()
    expect(pcaps.uploadPcap).toHaveBeenCalledOnce()
    expect(pcaps.getPcap).toHaveBeenCalledWith(651)
    expect(host.querySelector('.wb-name')?.textContent).toContain('existing.pcap')
    expect(document.body.textContent).toContain('文件已存在，已定位到记录 #651')
  })

  it('shows total packet counts and requests the second page', async () => {
    const open = Array.from(host.querySelectorAll('button')).find((b) => b.textContent?.trim() === '打开')!
    open.click()
    await flush()
    expect(Array.from(host.querySelectorAll('.mini-value')).map((n) => n.textContent)).toContain('284')
    host.querySelector<HTMLElement>('#tab-packets')!.click()
    await flush()
    host.querySelector<HTMLButtonElement>('.packet-pagination .btn-next')!.click()
    await flush()
    expect(pcaps.getPcapPackets).toHaveBeenLastCalledWith(651, 2, 100, '')
  })

  it('opens retained file text and renders the same bytes in Hex', async () => {
    const file = { id: 'a'.repeat(64), filename: 'report.txt', size: 5,
      mime_type: 'text/plain', binary_available: true, complete: true }
    vi.mocked(pcaps.getPcapFiles).mockResolvedValue({ items: [file], needs_analysis: false })
    vi.mocked(pcaps.getPcapFilePreview).mockResolvedValue({ ...file, offset: 0, length: 5,
      text: 'hello', hex: '68656c6c6f', encoding: 'utf-8', binary: false, has_more: false })
    Array.from(host.querySelectorAll('button')).find((b) => b.textContent?.trim() === '打开')!.click()
    await flush()
    host.querySelector<HTMLElement>('#tab-files')!.click()
    await flush()
    Array.from(host.querySelectorAll('button')).find((b) => b.textContent?.trim() === '查看')!.click()
    await flush()
    expect(pcaps.getPcapFilePreview).toHaveBeenCalledWith(651, file.id, 0)
    expect(document.querySelector('.file-text')?.textContent).toBe('hello')
    const hexTab = Array.from(document.querySelectorAll<HTMLElement>('[role=tab]'))
      .find((tab) => tab.textContent?.includes('Hex / ASCII'))!
    hexTab.click()
    await flush()
    expect(document.querySelector('.file-preview .hv-row .hv-hex')?.textContent).toBe('68 65 6c 6c 6f')
  })
})
