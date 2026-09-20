import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useSecurityAudit } from '../modules/operations/audit/composables/useSecurityAudit'
import type { AuditSummary, LogAnalysisResult } from '../api/audit'
import * as audit from '../api/audit'

vi.mock('../api/audit', () => ({ getAuditSummary: vi.fn(), analyzeLog: vi.fn() }))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const summary = (overrides: Partial<AuditSummary> = {}): AuditSummary => ({
  assets: 214, asset_risk: { High: 13, Low: 201 }, files: 12, file_risk: { Medium: 4 },
  pcaps: 9, anomalies: 3, anomaly_severity: { Low: 3 },
  leak_risk: { risk_level: 'High', protocols: { http: 12 }, high_risk_protocols: ['http'] },
  ...overrides,
})

const logResult = (overrides: Partial<LogAnalysisResult> = {}): LogAnalysisResult => ({
  log_summary: { line_count: 3, matches: { auth_failure: ['login failed for user admin'] } },
  findings: [{ engine: 'sigma_log_engine', rule_id: 'SIG-1', severity: 'High', confidence: 0.7,
    evidence: {}, recommendation: '检查认证日志', risk_score: 66, risk_level: 'High' }],
  risk: { score: 66, level: 'High' }, ...overrides,
})

let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async (): Promise<ReturnType<typeof useSecurityAudit>> => {
  let state: ReturnType<typeof useSecurityAudit>
  const Harness = defineComponent({
    setup() {
      state = useSecurityAudit()
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
  vi.mocked(audit.getAuditSummary).mockResolvedValue(summary())
  vi.mocked(audit.analyzeLog).mockResolvedValue(logResult())
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('security audit state', () => {
  it('loads the audit summary on mount', async () => {
    const state = await mount()
    expect(audit.getAuditSummary).toHaveBeenCalled()
    expect(state.summary.value?.assets).toBe(214)
    expect(state.summary.value?.leak_risk.high_risk_protocols).toEqual(['http'])
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('keeps a failed audit summary in the page state', async () => {
    vi.mocked(audit.getAuditSummary).mockRejectedValue(new Error('审计服务不可用'))
    const state = await mount()
    expect(state.error.value).toBe('审计服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.summary.value).toBeNull()
  })

  it('refuses to analyse an empty log', async () => {
    const state = await mount()
    state.logContent.value = '   \n  '
    await state.runLogAnalysis()
    expect(ElMessage.warning).toHaveBeenCalledWith('请输入待分析日志内容')
    expect(audit.analyzeLog).not.toHaveBeenCalled()
    expect(state.logRunning.value).toBe(false)
  })

  it('analyses the pasted log and keeps the result', async () => {
    const state = await mount()
    state.logContent.value = 'login failed for user admin'
    await state.runLogAnalysis()
    expect(audit.analyzeLog).toHaveBeenCalledWith('login failed for user admin')
    expect(state.logResult.value?.risk.score).toBe(66)
    expect(state.logRunning.value).toBe(false)
    expect(state.logError.value).toBe('')
  })

  it('keeps a failed log analysis in the log error instead of the page state', async () => {
    vi.mocked(audit.analyzeLog).mockRejectedValue(new Error('日志分析超时'))
    const state = await mount()
    state.logContent.value = 'login failed'
    await state.runLogAnalysis()
    expect(state.logError.value).toBe('日志分析超时')
    expect(state.error.value).toBe('')
    expect(state.logResult.value).toBeNull()
    expect(state.logRunning.value).toBe(false)
  })

  it('groups the server matches in the fixed order and drops the empty groups', async () => {
    const state = await mount()
    state.logResult.value = logResult({
      log_summary: {
        line_count: 5,
        matches: {
          traversal: ['../../etc/passwd'], auth_failure: ['login failed'], sql_error: [],
        },
      },
    })
    expect(state.matchGroups(state.logResult.value)).toEqual([
      { key: 'auth_failure', label: '认证失败', lines: ['login failed'] },
      { key: 'traversal', label: '路径穿越', lines: ['../../etc/passwd'] },
    ])
  })

  it('reports no match groups for a result without a log summary', async () => {
    const state = await mount()
    state.logResult.value = { findings: [], risk: { score: 0, level: 'Low' } } as unknown as LogAnalysisResult
    expect(state.matchGroups(state.logResult.value)).toEqual([])
  })
})