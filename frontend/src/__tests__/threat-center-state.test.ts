import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useRulesCenter } from '../modules/threat/composables/useRulesCenter'
import { useCveCenter } from '../modules/threat/composables/useCveCenter'
import { useIocCenter } from '../modules/threat/composables/useIocCenter'
import type { RuleItem } from '../api/rules'
import type { EngineInfo } from '../api/engine'
import type { LocalCve } from '../types/offline'
import type { Ioc, IocAssociation } from '../types/ioc'
import * as client from '../api/client'
import * as rules from '../api/rules'
import * as engine from '../api/engine'
import * as offline from '../api/offline'
import * as intelligence from '../api/intelligence'

vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))
vi.mock('../api/client', () => ({ apiGet: vi.fn(), apiPost: vi.fn(), apiUpload: vi.fn() }))
vi.mock('../api/rules', () => ({ listRules: vi.fn(), getRuleContent: vi.fn() }))
vi.mock('../api/engine', () => ({ getEngineRegistry: vi.fn() }))
vi.mock('../api/offline', () => ({ listLocalCves: vi.fn(), uploadOffline: vi.fn(), listOfflineResources: vi.fn() }))
vi.mock('../api/intelligence', () => ({ listIocs: vi.fn(), getIocAssociations: vi.fn() }))

const api = client as unknown as { apiGet: Mock; apiPost: Mock; apiUpload: Mock }
const rulesApi = rules as unknown as { listRules: Mock; getRuleContent: Mock }
const engineApi = engine as unknown as { getEngineRegistry: Mock }
const offlineApi = offline as unknown as { listLocalCves: Mock; uploadOffline: Mock; listOfflineResources: Mock }
const iocApi = intelligence as unknown as { listIocs: Mock; getIocAssociations: Mock }

const rule = (overrides: Partial<RuleItem> = {}): RuleItem => ({
  type: 'suricata', engine: 'suricata', name: 'ET scan', path: '/rules/et.rules',
  content: '', size: 120, rule_id: '1001', execution: 'active', ...overrides,
})

const engineInfo = (name: string): EngineInfo => ({ name, version: '1.0', label: name, rule_count: 3 })

const cve = (overrides: Partial<LocalCve> = {}): LocalCve => ({
  cve_id: 'CVE-2026-0001', source: 'offline', severity: 'High', cvss_score: 8.1,
  published: '2026-01-01T00:00:00', modified: '2026-01-02T00:00:00', description: 'a flaw',
  ...overrides,
} as LocalCve)

const ioc = (overrides: Partial<Ioc> = {}): Ioc => ({
  id: 1, type: 'ip', value: '10.0.0.1', source: 'misp', first_seen: '2026-01-01T00:00:00',
  last_seen: '2026-01-02T00:00:00', tags: ['c2'], created_at: '2026-01-01T00:00:00', ...overrides,
})

const association = (overrides: Partial<IocAssociation> = {}): IocAssociation => ({
  ioc: ioc(), findings: [], incidents: [], assets: [], ...overrides,
} as IocAssociation)

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
  localStorage.clear()
  rulesApi.listRules.mockResolvedValue({ items: [rule()], total: 1 })
  rulesApi.getRuleContent.mockResolvedValue({ content: 'alert tcp any any -> any any (msg:"x";)' })
  engineApi.getEngineRegistry.mockResolvedValue([engineInfo('suricata')])
  offlineApi.listLocalCves.mockResolvedValue({ items: [cve()], total: 1 })
  offlineApi.listOfflineResources.mockResolvedValue([
    { resource_type: 'grype_db', version: 'v5.0', count: 123 },
  ])
  offlineApi.uploadOffline.mockResolvedValue({ imported: 3, duplicates: 1 })
  iocApi.listIocs.mockResolvedValue({ items: [ioc()], total: 1 })
  iocApi.getIocAssociations.mockResolvedValue(association())
  api.apiPost.mockResolvedValue({})
  api.apiUpload.mockResolvedValue({ id: 'job-1', status: 'running' })
  api.apiGet.mockResolvedValue({ id: 'job-1', status: 'running' })
})

afterEach(() => {
  vi.useRealTimers()
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('rules centre state', () => {
  it('loads the inventory and the engine registry on mount', async () => {
    const state = await mount(() => useRulesCenter())
    expect(rulesApi.listRules).toHaveBeenCalledWith({ include_content: false })
    expect(engineApi.getEngineRegistry).toHaveBeenCalled()
    expect(state.rules.value.map((r) => r.name)).toEqual(['ET scan'])
    expect(state.engines.value.map((e) => e.name)).toEqual(['suricata'])
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('keeps a failed inventory load in the page state', async () => {
    rulesApi.listRules.mockRejectedValue(new Error('规则库不可用'))
    const state = await mount(() => useRulesCenter())
    expect(state.error.value).toBe('规则库不可用')
    expect(state.loading.value).toBe(false)
    expect(state.rules.value).toEqual([])
  })

  it('filters the rows by type and engine', async () => {
    rulesApi.listRules.mockResolvedValue({ items: [
      rule({ name: 'net', type: 'suricata', engine: 'suricata' }),
      rule({ name: 'file', type: 'yara', engine: 'yara' }),
      rule({ name: 'log', type: 'sigma', engine: 'sigma_log_engine' }),
    ], total: 3 })
    const state = await mount(() => useRulesCenter())
    state.activeType.value = 'yara'
    expect(state.filtered.value.map((r) => r.name)).toEqual(['file'])
    state.activeType.value = ''
    state.activeEngine.value = 'sigma_log_engine'
    expect(state.filtered.value.map((r) => r.name)).toEqual(['log'])
  })

  it('searches the name, the rule id and the path without case', async () => {
    rulesApi.listRules.mockResolvedValue({ items: [
      rule({ name: 'ET scan', rule_id: '1001', path: '/rules/et.rules' }),
      rule({ name: 'other', rule_id: '2002', path: '/rules/LOGIN.rules' }),
    ], total: 2 })
    const state = await mount(() => useRulesCenter())
    state.keyword.value = 'ET SCAN'
    expect(state.filtered.value.map((r) => r.name)).toEqual(['ET scan'])
    state.keyword.value = '2002'
    expect(state.filtered.value.map((r) => r.name)).toEqual(['other'])
    state.keyword.value = 'login'
    expect(state.filtered.value.map((r) => r.name)).toEqual(['other'])
  })

  it('pages the filtered rows 30 at a time', async () => {
    rulesApi.listRules.mockResolvedValue({
      items: Array.from({ length: 35 }, (_, i) => rule({ name: `r${i}` })), total: 35,
    })
    const state = await mount(() => useRulesCenter())
    expect(state.visible.value).toHaveLength(30)
    state.page.value = 2
    expect(state.visible.value).toHaveLength(5)
  })

  it('resets the page whenever a filter changes', async () => {
    const state = await mount(() => useRulesCenter())
    state.page.value = 3
    state.keyword.value = 'x'
    await nextTick()
    expect(state.page.value).toBe(1)
    state.page.value = 4
    state.activeEngine.value = 'suricata'
    await nextTick()
    expect(state.page.value).toBe(1)
  })

  it('lists the distinct types sorted', async () => {
    rulesApi.listRules.mockResolvedValue({ items: [
      rule({ type: 'yara' }), rule({ type: 'suricata' }), rule({ type: 'yara' }),
    ], total: 3 })
    const state = await mount(() => useRulesCenter())
    expect(state.types.value).toEqual(['suricata', 'yara'])
  })

  it('defaults the add dialog to the active type', async () => {
    const state = await mount(() => useRulesCenter())
    state.openAdd()
    expect(state.draft.rule_type).toBe('suricata')
    expect(state.dialog.value).toBe(true)
    state.dialog.value = false
    state.activeType.value = 'yara'
    state.openAdd()
    expect(state.draft.rule_type).toBe('yara')
    expect(state.dialog.value).toBe(true)
  })

  it('refuses a rule file larger than 1 MB', async () => {
    const state = await mount(() => useRulesCenter())
    const big = { raw: { size: 1024 * 1024 + 1 } as File }
    await state.readRule(big)
    expect(ElMessage.error).toHaveBeenCalledWith('规则文件不能超过 1 MB')
    expect(state.draft.content).toBe('')
  })

  it('reads the chosen file and derives the rule name', async () => {
    const state = await mount(() => useRulesCenter())
    const raw = { size: 10, name: 'ET scan 2026.rules', text: async () => 'alert tcp any any -> any any' } as unknown as File
    await state.readRule({ raw })
    expect(state.draft.content).toBe('alert tcp any any -> any any')
    expect(state.draft.name).toBe('ET_scan_2026')
  })

  it('validates and adds the rule, then reloads the inventory', async () => {
    const state = await mount(() => useRulesCenter())
    state.activeType.value = 'yara'
    state.openAdd()
    state.draft.name = 'malware'
    state.draft.content = 'rule m { condition: true }'
    await state.saveRule()
    expect(api.apiPost).toHaveBeenCalledWith('/rules', expect.objectContaining({
      rule_type: 'yara', name: 'malware', content: 'rule m { condition: true }',
    }))
    expect(state.activeType.value).toBe('yara')
    expect(state.dialog.value).toBe(false)
    expect(rulesApi.listRules).toHaveBeenCalledTimes(2)
    expect(ElMessage.success).toHaveBeenCalledWith('规则已校验并添加，对新检测任务生效')
    expect(state.saving.value).toBe(false)
  })

  it('reports a failed add without closing the dialog', async () => {
    api.apiPost.mockRejectedValue(new Error('规则语法错误'))
    const state = await mount(() => useRulesCenter())
    state.dialog.value = true
    await state.saveRule()
    expect(ElMessage.error).toHaveBeenCalledWith('Error: 规则语法错误')
    expect(state.dialog.value).toBe(true)
    expect(state.saving.value).toBe(false)
  })

  it('fetches the rule content lazily when a row is expanded', async () => {
    const state = await mount(() => useRulesCenter())
    const row = state.rules.value[0]
    await state.expandRule(row, [])
    expect(rulesApi.getRuleContent).not.toHaveBeenCalled()
    await state.expandRule(row, [row])
    expect(rulesApi.getRuleContent).toHaveBeenCalledWith(row)
    expect(row.content).toBe('alert tcp any any -> any any (msg:"x";)')
    await state.expandRule(row, [row])
    expect(rulesApi.getRuleContent).toHaveBeenCalledTimes(1)
  })
})

describe('CVE centre state', () => {
  it('loads the CVE page and the Grype library on mount', async () => {
    const state = await mount(() => useCveCenter())
    expect(offlineApi.listLocalCves).toHaveBeenCalledWith('', 1, 50)
    expect(offlineApi.listOfflineResources).toHaveBeenCalled()
    expect(state.items.value.map((i) => i.cve_id)).toEqual(['CVE-2026-0001'])
    expect(state.total.value).toBe(1)
    expect(state.library.value).toBe('Grype DB：v5.0，123 条 CVE')
    expect(state.loading.value).toBe(false)
  })

  it('annotates the library when no Grype DB was imported yet', async () => {
    offlineApi.listOfflineResources.mockResolvedValue([])
    const state = await mount(() => useCveCenter())
    expect(state.library.value).toBe('尚未导入 Grype DB')
  })

  it('keeps a failed load in the page state', async () => {
    offlineApi.listLocalCves.mockRejectedValue(new Error('离线库不可用'))
    const state = await mount(() => useCveCenter())
    expect(state.error.value).toBe('离线库不可用')
    expect(state.loading.value).toBe(false)
    expect(state.items.value).toEqual([])
  })

  it('searches from the first page', async () => {
    const state = await mount(() => useCveCenter())
    state.search.value = 'CVE-2026'
    state.page.value = 4
    state.searchCves()
    await flushing()
    expect(state.page.value).toBe(1)
    expect(offlineApi.listLocalCves).toHaveBeenLastCalledWith('CVE-2026', 1, 50)
  })

  it('tracks the Grype update job and remembers it', async () => {
    api.apiPost.mockResolvedValue({ id: 'job-7', status: 'running', stage: 'download' })
    api.apiGet.mockResolvedValue({ id: 'job-7', status: 'running', stage: 'download' })
    const state = await mount(() => useCveCenter())
    await state.updateGrype()
    await flushing()
    expect(api.apiPost).toHaveBeenCalledWith('/offline/grype/update')
    expect(state.job.value?.id).toBe('job-7')
    expect(state.busy.value).toBe(true)
    expect(localStorage.getItem('grype-library-job')).toBe('job-7')
    expect(api.apiGet).toHaveBeenCalledWith('/offline/grype/jobs/job-7')
  })

  it('polls the job until it completes and reloads the inventory', async () => {
    vi.useFakeTimers()
    const state = await mount(() => useCveCenter())
    state.search.value = ''
    await state.updateGrype()
    await flushing()
    expect(api.apiGet).toHaveBeenCalledTimes(1)
    api.apiGet.mockResolvedValue({ id: 'job-1', status: 'completed', result: { imported: 5, updated: 1, preserved: 2, version: 'v5' } })
    await vi.advanceTimersByTimeAsync(2000)
    await flushing()
    expect(state.job.value?.status).toBe('completed')
    expect(state.busy.value).toBe(false)
    expect(localStorage.getItem('grype-library-job')).toBeNull()
    expect(ElMessage.success).toHaveBeenCalledWith('Grype DB 导入完成')
    expect(offlineApi.listLocalCves).toHaveBeenCalledTimes(2)
  })

  it('stops polling and reports a failed job', async () => {
    vi.useFakeTimers()
    const state = await mount(() => useCveCenter())
    await state.updateGrype()
    await flushing()
    api.apiGet.mockResolvedValue({ id: 'job-1', status: 'failed', error: '下载校验失败' })
    await vi.advanceTimersByTimeAsync(2000)
    await flushing()
    expect(state.job.value?.status).toBe('failed')
    expect(state.busy.value).toBe(false)
    const calls = api.apiGet.mock.calls.length
    await vi.advanceTimersByTimeAsync(6000)
    await flushing()
    expect(api.apiGet.mock.calls.length).toBe(calls)
  })

  it('reports the errors of a CVE import instead of the counts', async () => {
    offlineApi.uploadOffline.mockResolvedValue({ imported: 0, duplicates: 0, errors: ['第 3 行缺少 cve_id', '第 9 行重复'] })
    const state = await mount(() => useCveCenter())
    await state.importCves({ raw: new File(['[]'], 'cves.json') })
    expect(ElMessage.error).toHaveBeenCalledWith('Error: 第 3 行缺少 cve_id; 第 9 行重复')
    expect(ElMessage.success).not.toHaveBeenCalled()
    expect(state.busy.value).toBe(false)
  })

  it('imports the CVE file and reports the counts', async () => {
    const state = await mount(() => useCveCenter())
    await state.importCves({ raw: new File(['[]'], 'cves.json') })
    expect(ElMessage.success).toHaveBeenCalledWith('新增 3 条，更新 1 条')
    expect(offlineApi.listLocalCves).toHaveBeenCalledTimes(2)
    expect(state.busy.value).toBe(false)
  })

  it('ignores an empty file selection', async () => {
    const state = await mount(() => useCveCenter())
    await state.importCves({})
    await state.importGrype({})
    expect(offlineApi.uploadOffline).not.toHaveBeenCalled()
    expect(api.apiUpload).not.toHaveBeenCalled()
    expect(state.busy.value).toBe(false)
  })

  it('adds a CVE by hand and closes the dialog', async () => {
    const state = await mount(() => useCveCenter())
    state.dialog.value = true
    state.draft.cve_id = 'CVE-2026-9999'
    await state.saveCve()
    expect(api.apiPost).toHaveBeenCalledWith('/offline/cves', state.draft)
    expect(state.dialog.value).toBe(false)
    expect(ElMessage.success).toHaveBeenCalledWith('CVE 已添加')
    expect(offlineApi.listLocalCves).toHaveBeenCalledTimes(2)
  })

  it('resumes the remembered job on mount and clears the timer on unmount', async () => {
    vi.useFakeTimers()
    localStorage.setItem('grype-library-job', 'job-9')
    api.apiGet.mockResolvedValue({ id: 'job-9', status: 'running' })
    const state = await mount(() => useCveCenter())
    expect(api.apiGet).toHaveBeenCalledWith('/offline/grype/jobs/job-9')
    expect(state.job.value?.id).toBe('job-9')
    expect(state.busy.value).toBe(true)
    const calls = api.apiGet.mock.calls.length
    app!.unmount()
    await vi.advanceTimersByTimeAsync(8000)
    await flushing()
    expect(api.apiGet.mock.calls.length).toBe(calls)
  })
})

describe('IOC centre state', () => {
  it('loads the indicators on mount', async () => {
    const state = await mount(() => useIocCenter())
    expect(iocApi.listIocs).toHaveBeenCalledWith({ type: '', source: '', search: '', page: 1, page_size: 50 })
    expect(state.items.value.map((i) => i.value)).toEqual(['10.0.0.1'])
    expect(state.total.value).toBe(1)
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('keeps a failed load in the page state', async () => {
    iocApi.listIocs.mockRejectedValue(new Error('情报库不可用'))
    const state = await mount(() => useIocCenter())
    expect(state.error.value).toBe('情报库不可用')
    expect(state.items.value).toEqual([])
    expect(state.loading.value).toBe(false)
  })

  it('resets to the first page and reloads', async () => {
    const state = await mount(() => useIocCenter())
    state.filters.page = 5
    state.reset()
    await flushing()
    expect(state.filters.page).toBe(1)
    expect(iocApi.listIocs).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1 }))
  })

  it('opens the association drawer of a row', async () => {
    const state = await mount(() => useIocCenter())
    await state.open(state.items.value[0])
    expect(iocApi.getIocAssociations).toHaveBeenCalledWith(1)
    expect(state.detail.value?.ioc.id).toBe(1)
    expect(state.drawer.value).toBe(true)
  })

  it('reports a failed association read without opening the drawer', async () => {
    iocApi.getIocAssociations.mockRejectedValue(new Error('关联查询超时'))
    const state = await mount(() => useIocCenter())
    await state.open(state.items.value[0])
    expect(ElMessage.error).toHaveBeenCalledWith('关联查询超时')
    expect(state.drawer.value).toBe(false)
    expect(state.detail.value).toBeNull()
  })

  it('toggles the enabled flag of a row and reloads', async () => {
    const state = await mount(() => useIocCenter())
    await state.toggle(ioc({ metadata: { enabled: true } }))
    expect(api.apiPost).toHaveBeenCalledWith('/intelligence/1/toggle', { enabled: false })
    await state.toggle(ioc({ metadata: { enabled: false } }))
    expect(api.apiPost).toHaveBeenLastCalledWith('/intelligence/1/toggle', { enabled: true })
    expect(iocApi.listIocs).toHaveBeenCalledTimes(3)
  })

  it('reports a failed toggle', async () => {
    api.apiPost.mockRejectedValue(new Error('指标不存在'))
    const state = await mount(() => useIocCenter())
    await state.toggle(ioc())
    expect(ElMessage.error).toHaveBeenCalledWith('Error: 指标不存在')
  })
})