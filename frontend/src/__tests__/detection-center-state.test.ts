import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useDetectionCenter } from '../modules/operations/detections/composables/useDetectionCenter'
import type { DetectionFinding, FindingDetail } from '../types/finding'
import * as detections from '../api/detections'
import * as engine from '../api/engine'

vi.mock('../api/detections', () => ({ listDetections: vi.fn(), getDetection: vi.fn() }))
vi.mock('../api/engine', () => ({ getEngineRegistry: vi.fn(), runPipeline: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const finding = (overrides: Partial<DetectionFinding> = {}): DetectionFinding => ({
  id: 31, target_type: 'host', target_id: '10.0.0.9', engine: 'sigma_log_engine',
  rule_id: 'proc_creation_win_susp', severity: 'High', confidence: 0.72, evidence: {},
  recommendation: '隔离主机', risk_score: 78, risk_level: 'High',
  timestamp: '2026-09-19T10:00:00', created_at: '2026-09-19T10:00:00', ...overrides,
})

const findingDetail = (overrides: Partial<FindingDetail> = {}): FindingDetail => ({
  detection: finding(), related_incidents: [], pcap: null, alert: null, ...overrides,
})

const engineInfo = (overrides: Partial<engine.EngineInfo> = {}): engine.EngineInfo => ({
  name: 'sigma_log_engine', version: '1.0.0', active_rule_files: 0, label: 'Sigma 日志引擎',
  detection_engine: 'sigma_log_engine', detection_count: 12, ...overrides,
})

const pipelineRun = (overrides: Partial<engine.PipelineRunResult> = {}): engine.PipelineRunResult => ({
  target_type: 'log', findings: [{ engine: 'sigma_log_engine', severity: 'High', risk_score: 60 }],
  risk_score: 60, risk_level: 'Medium', summary: { engine_count: 1, finding_count: 1 }, ...overrides,
})

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async (): Promise<ReturnType<typeof useDetectionCenter>> => {
  let state: ReturnType<typeof useDetectionCenter>
  const Harness = defineComponent({
    setup() {
      state = useDetectionCenter()
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
  vi.mocked(detections.listDetections).mockResolvedValue({ items: [finding()], total: 76, page: 1, page_size: 50 })
  vi.mocked(detections.getDetection).mockResolvedValue(findingDetail())
  vi.mocked(engine.getEngineRegistry).mockResolvedValue([engineInfo()])
  vi.mocked(engine.runPipeline).mockResolvedValue(pipelineRun())
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('detection centre state', () => {
  it('loads the first page on mount with the active filters and keeps the server total', async () => {
    const state = await mount()
    expect(detections.listDetections).toHaveBeenCalledWith({
      search: '', severity: '', engine: '', page: 1, page_size: 50,
    })
    expect(state.items.value).toHaveLength(1)
    expect(state.total.value).toBe(76)
    expect(state.loading.value).toBe(false)
  })

  it('builds the engine options from the registry with the counts findings are stored under', async () => {
    vi.mocked(engine.getEngineRegistry).mockResolvedValue([
      engineInfo(),
      engineInfo({ name: 'zeek_adapter', detection_engine: undefined, detection_count: 3, label: undefined }),
      engineInfo({ name: 'suricata_adapter', detection_engine: 'suricata', detection_count: undefined, label: 'Suricata' }),
    ])
    const state = await mount()
    expect(state.engineOptions.value).toEqual([
      { label: 'Sigma 日志引擎 (12)', value: 'sigma_log_engine' },
      { label: 'zeek_adapter (3)', value: 'zeek_adapter' },
      { label: 'Suricata (0)', value: 'suricata' },
    ])
  })

  it('keeps the engine options empty when the registry request fails', async () => {
    vi.mocked(engine.getEngineRegistry).mockRejectedValue(new Error('引擎注册表不可用'))
    const state = await mount()
    expect(state.engineOptions.value).toEqual([])
    expect(detections.listDetections).toHaveBeenCalled()
    expect(state.error.value).toBe('')
  })

  it('returns to the first page when the filter bar resets', async () => {
    const state = await mount()
    state.filters.search = 'sigma'
    state.filters.page = 4
    state.reset()
    await flushing()
    expect(detections.listDetections).toHaveBeenLastCalledWith({
      search: 'sigma', severity: '', engine: '', page: 1, page_size: 50,
    })
  })

  it('opens the detail drawer of the clicked row only once the detail arrives', async () => {
    let resolve: (value: FindingDetail) => void = () => {}
    vi.mocked(detections.getDetection).mockReturnValue(new Promise((r) => { resolve = r }))
    const state = await mount()
    const pending = state.open(finding())
    await flushing()
    expect(detections.getDetection).toHaveBeenCalledWith(31)
    expect(state.drawer.value).toBe(false)
    resolve(findingDetail({ related_incidents: [{ id: 5 } as never] }))
    await pending
    expect(state.drawer.value).toBe(true)
    expect(state.detail.value?.related_incidents).toHaveLength(1)
  })

  it('reports the reason and leaves the drawer closed when the detail cannot be read', async () => {
    vi.mocked(detections.getDetection).mockRejectedValue(new Error('检测不存在'))
    const state = await mount()
    await state.open(finding())
    expect(ElMessage.error).toHaveBeenCalledWith('检测不存在')
    expect(state.drawer.value).toBe(false)
    expect(state.detail.value).toBeNull()
  })

  it('keeps a failed finding load in the page state', async () => {
    vi.mocked(detections.listDetections).mockRejectedValue(new Error('检测服务不可用'))
    const state = await mount()
    expect(state.error.value).toBe('检测服务不可用')
    expect(state.loading.value).toBe(false)
  })

  it('runs the manual pipeline with the split log lines and the parsed JSON body', async () => {
    const state = await mount()
    state.pipelineForm.target_type = 'log'
    state.pipelineForm.log_lines = 'first line\n\nsecond line'
    state.pipelineForm.data = '{"protocol_summary": {"http": 10}}'
    await state.runPipelineNow()
    expect(engine.runPipeline).toHaveBeenCalledWith({
      target_type: 'log',
      log_lines: ['first line', 'second line'],
      data: { protocol_summary: { http: 10 } },
    })
    expect(ElMessage.success).toHaveBeenCalledWith('流水线执行完成')
    expect(state.pipelineResult.value?.summary.finding_count).toBe(1)
    expect(state.pipelineRunning.value).toBe(false)

    state.pipelineForm.log_lines = ''
    state.pipelineForm.data = ''
    await state.runPipelineNow()
    expect(engine.runPipeline).toHaveBeenLastCalledWith({ target_type: 'log', log_lines: undefined, data: {} })
  })

  it('refuses to run the pipeline with a malformed JSON body', async () => {
    const state = await mount()
    state.pipelineForm.target_type = 'text'
    state.pipelineForm.data = '{not json'
    await state.runPipelineNow()
    expect(engine.runPipeline).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalled()
    expect(state.pipelineRunning.value).toBe(false)
    expect(state.pipelineResult.value).toBeNull()
  })

  it('reports a failed pipeline run and clears the previous result', async () => {
    const state = await mount()
    state.pipelineResult.value = pipelineRun()
    vi.mocked(engine.runPipeline).mockRejectedValue(new Error('引擎未启用'))
    await state.runPipelineNow()
    expect(ElMessage.error).toHaveBeenCalledWith('引擎未启用')
    expect(state.pipelineResult.value).toBeNull()
    expect(state.pipelineRunning.value).toBe(false)
  })
})