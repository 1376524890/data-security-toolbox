import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { computed, createApp, defineComponent, nextTick, ref, type App } from 'vue'
import { useEngineDetail } from '../modules/engines/composables/useEngineDetail'
import type { IntegrationStatus } from '../types/integration'
import type { DetectionFinding } from '../types/finding'
import type { Task } from '../types/task'
import type { HealthResponse } from '../api/health'
import type { EngineInfo } from '../api/engine'
import type { RuleItem } from '../api/rules'
import * as integrations from '../api/integrations'
import * as health from '../api/health'
import * as engine from '../api/engine'
import * as tasks from '../api/tasks'
import * as detections from '../api/detections'
import * as rules from '../api/rules'

vi.mock('../api/integrations', () => ({ listIntegrations: vi.fn() }))
vi.mock('../api/health', () => ({ getHealth: vi.fn() }))
vi.mock('../api/engine', () => ({ getEngineRegistry: vi.fn() }))
vi.mock('../api/tasks', () => ({ listTasks: vi.fn() }))
vi.mock('../api/detections', () => ({ listDetections: vi.fn() }))
vi.mock('../api/rules', () => ({ listRules: vi.fn(), getRuleContent: vi.fn() }))

const integration = (overrides: Partial<IntegrationStatus> = {}): IntegrationStatus => ({
  name: 'sigma', adapter_version: '1.0.0', version: '1.0.0', installed: true, enabled: true,
  healthy: true, runtime_version: 'python3.11', supported_types: ['log'], capabilities: [],
  last_check: '2026-09-19T09:00:00', status: 'ok', message: '', rule_count: 120, ...overrides,
})

const engineInfo = (overrides: Partial<EngineInfo> = {}): EngineInfo => ({
  name: 'sigma_log_engine', version: '1.0.0', label: 'Sigma 日志引擎', slug: 'sigma',
  detection_engine: 'sigma_log_engine', detection_count: 12, rule_count: 42, ...overrides,
})

const rule = (overrides: Partial<RuleItem> = {}): RuleItem => ({
  type: 'sigma', engine: 'sigma_log_engine', name: 'proc_creation.yml',
  path: '/rules/sigma/proc_creation.yml', content: '', size: 1024, rule_id: 'SIG-1',
  execution: 'active', ...overrides,
})

const finding = (overrides: Partial<DetectionFinding> = {}): DetectionFinding => ({
  id: 5, target_type: 'host', target_id: '10.0.0.1', engine: 'sigma_log_engine', rule_id: 'SIG-1',
  severity: 'High', confidence: 0.8, evidence: {}, recommendation: '关注该主机', risk_score: 70,
  risk_level: 'High', timestamp: '2026-09-19T10:00:00', created_at: '2026-09-19T10:00:00', ...overrides,
})

const task = (overrides: Partial<Task> = {}): Task => ({
  id: 9, kind: 'pcap', status: 'Success', progress: 100, current_stage: 'done', log: '',
  payload: {}, result: {}, error: '', created_at: '2026-09-19T10:00:00', ...overrides,
})

const healthResponse = (overrides: Partial<HealthResponse> = {}): HealthResponse => ({
  status: 'ok', service: 'api', api: '1.0.0', database: 'ok', redis: 'ok',
  celery: { broker: 'redis', workers: 1, running: 0, queued: 0 }, analysis_worker: 'ready',
  worker_capabilities: [], tshark: { available: true, version: '4.0' },
  zeek: { available: false, version: '' }, suricata: { available: false, version: '', rule_count: 0 },
  storage_usage_bytes: 0, storage_max_bytes: 0,
  queue: { pending: 0, running: 0, oldest_pending_age: 0 },
  probe: { count: 1, online: 1, degraded: 0, offline: 0, auth_error: 0 }, ...overrides,
})

let app: App | undefined
let host: HTMLElement | undefined
let routeName = ref('sigma')

const flushing = async () => {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mount = async (initial = 'sigma'): Promise<ReturnType<typeof useEngineDetail>> => {
  routeName = ref(initial)
  let state: ReturnType<typeof useEngineDetail>
  const Harness = defineComponent({
    setup() {
      state = useEngineDetail(computed(() => routeName.value))
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

const thirtyFiveRules = () => Array.from({ length: 35 }, (_, index) => rule({
  name: `rule-${String(index).padStart(2, '0')}.yml`,
  rule_id: `SIG-${index}`,
  path: `/rules/sigma/rule-${index}.yml`,
}))

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(integrations.listIntegrations).mockResolvedValue([integration()])
  vi.mocked(health.getHealth).mockResolvedValue(healthResponse())
  vi.mocked(engine.getEngineRegistry).mockResolvedValue([engineInfo()])
  vi.mocked(tasks.listTasks).mockResolvedValue({ items: [task()], total: 1, page: 1, page_size: 20 })
  vi.mocked(detections.listDetections).mockResolvedValue({ items: [finding()], total: 88, page: 1, page_size: 20 })
  vi.mocked(rules.listRules).mockResolvedValue({ items: [rule()], total: 1 })
  vi.mocked(rules.getRuleContent).mockResolvedValue(rule({ content: 'title: proc_creation' }))
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('engine detail state', () => {
  it('loads the integrations, the health, the registry and the recent tasks on mount', async () => {
    const state = await mount()
    expect(integrations.listIntegrations).toHaveBeenCalled()
    expect(health.getHealth).toHaveBeenCalled()
    expect(engine.getEngineRegistry).toHaveBeenCalled()
    expect(tasks.listTasks).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(state.integrations.value).toHaveLength(1)
    expect(state.health.value?.analysis_worker).toBe('ready')
    expect(state.tasks.value).toHaveLength(1)
    expect(state.loading.value).toBe(false)
  })

  it('resolves the console route through the registry so rules and findings use the engine name', async () => {
    const state = await mount('sigma')
    expect(rules.listRules).toHaveBeenCalledWith({ engine: 'sigma_log_engine', include_content: false })
    expect(detections.listDetections).toHaveBeenCalledWith({ engine: 'sigma_log_engine', page: 1, page_size: 20 })
    expect(state.engineMeta.value?.name).toBe('sigma_log_engine')
    expect(state.findingsTotal.value).toBe(88)
    expect(state.rules.value).toHaveLength(1)
  })

  it('falls back to the route name when the registry has no entry for it', async () => {
    vi.mocked(engine.getEngineRegistry).mockResolvedValue([])
    const state = await mount('zeek')
    expect(rules.listRules).toHaveBeenCalledWith({ engine: 'zeek', include_content: false })
    expect(state.engineMeta.value).toBeUndefined()
    expect(state.isSigma.value).toBe(false)
  })

  it('takes the rule count from the registry first, then the matching adapter', async () => {
    const fromRegistry = await mount()
    expect(fromRegistry.ruleCount.value).toBe(42)
    expect(fromRegistry.integration.value?.rule_count).toBe(42)

    vi.mocked(engine.getEngineRegistry).mockResolvedValue([engineInfo({ rule_count: undefined })])
    const fromAdapter = await mount()
    expect(fromAdapter.ruleCount.value).toBe(120)
    expect(fromAdapter.integration.value?.rule_count).toBe(120)

    vi.mocked(integrations.listIntegrations).mockResolvedValue([integration({ rule_count: undefined })])
    const none = await mount()
    expect(none.ruleCount.value).toBeNull()
    expect(none.integration.value?.rule_count).toBeUndefined()
  })

  it('matches the integration case-insensitively and keeps none when the engine is absent', async () => {
    vi.mocked(integrations.listIntegrations).mockResolvedValue([integration({ name: 'Sigma' })])
    const matched = await mount()
    expect(matched.integration.value?.name).toBe('Sigma')

    vi.mocked(integrations.listIntegrations).mockResolvedValue([integration({ name: 'suricata' })])
    const missing = await mount()
    expect(missing.integration.value).toBeNull()
  })

  it('flags the sigma engine for the console route and for the registry name', async () => {
    vi.mocked(engine.getEngineRegistry).mockResolvedValue([])
    const byRegistryName = await mount('sigma_log_engine')
    expect(byRegistryName.isSigma.value).toBe(true)

    const other = await mount('zeek')
    expect(other.isSigma.value).toBe(false)
  })

  it('paginates the rule list in pages of 30', async () => {
    vi.mocked(rules.listRules).mockResolvedValue({ items: thirtyFiveRules(), total: 35 })
    const state = await mount()
    expect(state.filteredRules.value).toHaveLength(35)
    expect(state.visibleRules.value).toHaveLength(30)
    state.rulePage.value = 2
    expect(state.visibleRules.value).toHaveLength(5)
  })

  it('filters the rules by name, id or path and returns to the first page', async () => {
    vi.mocked(rules.listRules).mockResolvedValue({ items: thirtyFiveRules(), total: 35 })
    const state = await mount()
    state.rulePage.value = 2
    state.ruleKeyword.value = 'SIG-7'
    await flushing()
    expect(state.filteredRules.value.map((item) => item.rule_id)).toEqual(['SIG-7'])
    expect(state.rulePage.value).toBe(1)

    state.ruleKeyword.value = '/rules/sigma/rule-3.yml'
    await flushing()
    expect(state.filteredRules.value.map((item) => item.name)).toEqual(['rule-03.yml'])

    state.ruleKeyword.value = 'RULE-0'
    await flushing()
    expect(state.filteredRules.value).toHaveLength(10)
  })

  it('reloads the page when the route name changes and returns to the first rule page', async () => {
    const state = await mount('sigma')
    state.rulePage.value = 3
    vi.mocked(detections.listDetections).mockClear()
    routeName.value = 'zeek'
    await flushing()
    expect(detections.listDetections).toHaveBeenCalledWith({ engine: 'zeek', page: 1, page_size: 20 })
    expect(state.rulePage.value).toBe(1)
    expect(state.findingsTotal.value).toBe(88)
  })

  it('loads a rule content once, only for an expanded row', async () => {
    const state = await mount()
    const row = rule()
    await state.expandRule(row, [])
    expect(rules.getRuleContent).not.toHaveBeenCalled()

    await state.expandRule(row, [row])
    expect(rules.getRuleContent).toHaveBeenCalledWith(row)
    expect(row.content).toBe('title: proc_creation')

    await state.expandRule(row, [row])
    expect(rules.getRuleContent).toHaveBeenCalledTimes(1)
  })

  it('keeps a failed rule content load and a failed page load in the page state', async () => {
    const state = await mount()
    const row = rule()
    vi.mocked(rules.getRuleContent).mockRejectedValue(new Error('规则文件不存在'))
    await state.expandRule(row, [row])
    expect(state.error.value).toBe('规则文件不存在')

    vi.mocked(integrations.listIntegrations).mockRejectedValue(new Error('集成服务不可用'))
    await state.load()
    expect(state.error.value).toBe('集成服务不可用')
    expect(state.loading.value).toBe(false)
  })
})
