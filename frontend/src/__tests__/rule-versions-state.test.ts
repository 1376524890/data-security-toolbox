import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRuleVersions } from '../modules/collection/composables/useRuleVersions'
import type { Probe } from '../api/probes'
import type { RuleSetSummary, RuleSetVersion } from '../api/ruleSets'
import * as probes from '../api/probes'
import * as ruleSets from '../api/ruleSets'

vi.mock('../api/probes', () => ({ listProbes: vi.fn() }))
vi.mock('../api/ruleSets', () => ({
  listRuleSets: vi.fn(), listRuleSetVersions: vi.fn(),
  publishRuleSetVersion: vi.fn(), rollbackRuleSetVersion: vi.fn(),
}))
vi.mock('element-plus', () => ({
  ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
  ElMessageBox: { confirm: vi.fn() },
}))

const probe = (id: number, metadata: Record<string, unknown> = {}): Probe => ({
  id, name: `probe-${id}`, hostname: `host-${id}`, ip_address: `10.0.0.${id}`,
  status: 'online', metadata, created_at: '',
}) as Probe

const version = (overrides: Partial<RuleSetVersion> = {}): RuleSetVersion => ({
  id: 1, version: 'rel-1', status: 'published', rule_count: 12, sha256: 'f'.repeat(64),
  schema_version: '1', engine_version: '3.5.0', min_agent_version: '', origin_version: '',
  changelog: '', published_by: 'admin', created_at: '2026-09-19T10:00:00', ...overrides,
})

const ruleSetSummary = (overrides: Partial<RuleSetSummary> = {}): RuleSetSummary => ({
  id: 7, name: '默认规则集', description: '', active_version: version({ id: 2, version: 'rel-2' }),
  working_rule_count: 3, capabilities: {}, ...overrides,
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
  vi.mocked(ElMessageBox.confirm).mockResolvedValue('confirm' as never)
  vi.mocked(probes.listProbes).mockResolvedValue({ items: [probe(12)], total: 1, page: 1, page_size: 200 })
  vi.mocked(ruleSets.listRuleSets).mockResolvedValue({ items: [ruleSetSummary()], total: 1 })
  vi.mocked(ruleSets.listRuleSetVersions).mockResolvedValue({
    items: [version({ id: 2, version: 'rel-2' }), version({ id: 1, version: 'rel-1', status: 'superseded' })],
    total: 2, active_version: 'rel-2',
  })
  vi.mocked(ruleSets.publishRuleSetVersion).mockResolvedValue(
    version({ id: 3, version: 'rel-3', rule_count: 14 }))
  vi.mocked(ruleSets.rollbackRuleSetVersion).mockResolvedValue(
    version({ id: 4, version: 'rel-4', origin_version: 'rel-1' }))
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('rule version console state', () => {
  it('loads the active rule set with its versions and the probe list', async () => {
    const state = await mount(() => useRuleVersions())
    expect(ruleSets.listRuleSets).toHaveBeenCalledWith()
    expect(ruleSets.listRuleSetVersions).toHaveBeenCalledWith(7)
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(state.ruleSet.value?.id).toBe(7)
    expect(state.versions.value.map((item) => item.version)).toEqual(['rel-2', 'rel-1'])
    expect(state.loading.value).toBe(false)
  })

  it('classifies probes by the version they report, not by what was published', async () => {
    vi.mocked(probes.listProbes).mockResolvedValue({
      items: [
        probe(1, { current_ruleset_version: 'rel-2' }),
        probe(2, { current_ruleset_version: 'rel-1' }),
        probe(3, { current_ruleset_version: 'rel-2', ruleset_last_error: '下载超时' }),
      ],
      total: 3, page: 1, page_size: 200,
    })
    const state = await mount(() => useRuleVersions())
    expect(state.outOfDateProbes.value.map((item) => item.id)).toEqual([2])
    expect(state.failedProbes.value.map((item) => item.id)).toEqual([3])
  })

  it('publishes a stamped version and reloads', async () => {
    const state = await mount(() => useRuleVersions())
    state.openPublish()
    state.draft.changelog = '新增邮箱规则'
    const stamp = state.draft.version
    await state.publish()
    expect(ruleSets.publishRuleSetVersion).toHaveBeenCalledWith(7, {
      version: stamp, changelog: '新增邮箱规则', min_agent_version: '',
    })
    expect(ElMessage.success).toHaveBeenCalled()
  })

  it('rolls back by publishing the old version as a new one', async () => {
    const state = await mount(() => useRuleVersions())
    await state.rollback(version({ id: 1, version: 'rel-1' }))
    expect(ruleSets.rollbackRuleSetVersion).toHaveBeenCalledWith(7, {
      to_version: 'rel-1', changelog: '回滚到 rel-1',
    })
  })
})
