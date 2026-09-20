import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useScanProfiles } from '../modules/data-security/composables/useScanProfiles'
import { useRuleVersions } from '../modules/data-security/composables/useRuleVersions'
import type { Probe } from '../api/probes'
import type { RuleSetSummary, RuleSetVersion } from '../api/ruleSets'
import type { ScanProfile } from '../api/scanProfiles'
import * as probes from '../api/probes'
import * as ruleSets from '../api/ruleSets'
import * as scanProfiles from '../api/scanProfiles'

vi.mock('../api/probes', () => ({ listProbes: vi.fn() }))
vi.mock('../api/scanProfiles', () => ({
  listScanProfiles: vi.fn(), createScanProfile: vi.fn(), updateScanProfile: vi.fn(),
  deleteScanProfile: vi.fn(), runScanProfile: vi.fn(),
}))
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

const profile = (overrides: Partial<ScanProfile> = {}): ScanProfile => ({
  id: 3, name: '业务服务器-敏感数据', version: 2, description: '',
  include_paths: ['/srv/data'], exclude_paths: [], file_types: [],
  max_files: 200, max_dirs: 500, max_depth: 3, max_runtime_seconds: 120,
  max_bytes_read: 512 * 1024 * 1024, max_single_file_size: 2 * 1024 * 1024,
  max_full_hash_size: 8 * 1024 * 1024, large_file_sampling: true,
  sample_block_size: 64 * 1024, max_sample_rows: 25, max_cpu_seconds: 0, max_rss_mb: 0,
  xlsx_max_entries: 512, xlsx_max_uncompressed_bytes: 64 * 1024 * 1024,
  xlsx_max_compression_ratio: 200, xlsx_max_shared_strings: 200000,
  xlsx_max_sheets: 32, xlsx_max_columns: 256, xlsx_max_rows: 200,
  enabled: true, scheduled: false, interval_seconds: 3600,
  created_by: 'admin', created_at: '2026-09-18T10:00:00', updated_at: '2026-09-19T10:00:00',
  ...overrides,
})

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
  vi.mocked(scanProfiles.listScanProfiles).mockResolvedValue({
    items: [profile(), profile({ id: 4, name: '只读目录', enabled: false, scheduled: true })],
    total: 45, page: 1, page_size: 20,
  })
  vi.mocked(scanProfiles.createScanProfile).mockResolvedValue(profile({ id: 9 }))
  vi.mocked(scanProfiles.updateScanProfile).mockResolvedValue(profile())
  vi.mocked(scanProfiles.deleteScanProfile).mockResolvedValue()
  vi.mocked(scanProfiles.runScanProfile).mockResolvedValue({ id: 55, status: 'Pending' })

  vi.mocked(ruleSets.listRuleSets).mockResolvedValue({ items: [ruleSetSummary()], total: 1 })
  vi.mocked(ruleSets.listRuleSetVersions).mockResolvedValue({
    items: [version({ id: 2, version: 'rel-2' }), version({ id: 1, version: 'rel-1', status: 'superseded' })],
    total: 2, active_version: 'rel-2',
  })
  vi.mocked(ruleSets.publishRuleSetVersion).mockResolvedValue(version({ id: 3, version: 'rel-3', rule_count: 14 }))
  vi.mocked(ruleSets.rollbackRuleSetVersion).mockResolvedValue(
    version({ id: 4, version: 'rel-4', origin_version: 'rel-1' }),
  )
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('scan profile console state', () => {
  it('loads the profile page together with the probe list and keeps the server total', async () => {
    const state = await mount(() => useScanProfiles())
    expect(scanProfiles.listScanProfiles).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(state.profiles.value.map((item) => item.id)).toEqual([3, 4])
    expect(state.total.value).toBe(45)
    expect(state.probes.value.map((item) => item.id)).toEqual([12])
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('counts enabled and scheduled rows without a second request', async () => {
    const state = await mount(() => useScanProfiles())
    expect(state.activeProfiles.value).toBe(1)
    expect(state.scheduledProfiles.value).toBe(1)
    vi.mocked(scanProfiles.listScanProfiles).mockClear()
    await state.load()
    expect(state.activeProfiles.value).toBe(1)
    expect(scanProfiles.listScanProfiles).toHaveBeenCalledTimes(1)
  })

  it('moves the pager and re-queries that page', async () => {
    const state = await mount(() => useScanProfiles())
    vi.mocked(scanProfiles.listScanProfiles).mockClear()
    state.setPage(3)
    await flushing()
    expect(state.page.value).toBe(3)
    expect(scanProfiles.listScanProfiles).toHaveBeenCalledWith({ page: 3, page_size: 20 })
  })

  const draftPaths = (state: ReturnType<typeof useScanProfiles>) => ({
    include: state.includePathsText.value, exclude: state.excludePathsText.value,
  })

  it('resets the draft for a new profile and fills it from the row when editing', async () => {
    const state = await mount(() => useScanProfiles())
    state.includePathsText.value = '/leftover'
    state.openCreate()
    expect(state.editingId.value).toBeNull()
    expect(state.dialog.value).toBe(true)
    expect(draftPaths(state)).toEqual({ include: '', exclude: '' })
    expect(state.draft.name).toBe('')

    state.openEdit(profile({ id: 4, name: '只读目录', include_paths: ['/srv/a', '/srv/b'], exclude_paths: ['/srv/a/tmp'] }))
    expect(state.editingId.value).toBe(4)
    expect(state.draft.name).toBe('只读目录')
    expect(draftPaths(state)).toEqual({ include: '/srv/a\n/srv/b', exclude: '/srv/a/tmp' })
  })

  it('splits the path textareas and either patches the edited row or creates a new one', async () => {
    const state = await mount(() => useScanProfiles())
    state.openEdit(profile({ id: 4 }))
    state.includePathsText.value = ' /srv/a \n\n/srv/b\n'
    state.excludePathsText.value = '/srv/a/tmp'
    await state.save()
    expect(scanProfiles.updateScanProfile).toHaveBeenCalledWith(4, expect.objectContaining({
      include_paths: ['/srv/a', '/srv/b'], exclude_paths: ['/srv/a/tmp'],
    }))
    expect(scanProfiles.createScanProfile).not.toHaveBeenCalled()
    expect(state.dialog.value).toBe(false)
    expect(state.saving.value).toBe(false)
    expect(ElMessage.success).toHaveBeenCalled()
    expect(scanProfiles.listScanProfiles).toHaveBeenCalledTimes(2)

    state.openCreate()
    state.includePathsText.value = '/srv/x'
    await state.save()
    expect(scanProfiles.createScanProfile).toHaveBeenCalledWith(
      expect.objectContaining({ include_paths: ['/srv/x'], exclude_paths: [] }),
    )
    expect(scanProfiles.updateScanProfile).toHaveBeenCalledTimes(1)
  })

  it('surfaces a refused save instead of a generic failure', async () => {
    const state = await mount(() => useScanProfiles())
    vi.mocked(scanProfiles.updateScanProfile).mockRejectedValue(new Error('版本冲突'))
    state.openEdit(profile({ id: 4 }))
    await state.save()
    expect(ElMessage.error).toHaveBeenCalledWith('版本冲突')
    expect(state.dialog.value).toBe(true)
    expect(state.saving.value).toBe(false)
  })

  it('asks before deleting and skips the request when the confirmation is dismissed', async () => {
    const state = await mount(() => useScanProfiles())
    vi.mocked(ElMessageBox.confirm).mockRejectedValue(new Error('cancel'))
    await state.remove(profile({ id: 4, name: '只读目录' }))
    expect(scanProfiles.deleteScanProfile).not.toHaveBeenCalled()

    vi.mocked(ElMessageBox.confirm).mockResolvedValue('confirm' as never)
    await state.remove(profile({ id: 4, name: '只读目录' }))
    expect(scanProfiles.deleteScanProfile).toHaveBeenCalledWith(4)
    expect(ElMessage.success).toHaveBeenCalledWith('已删除')
    expect(scanProfiles.listScanProfiles).toHaveBeenCalledTimes(2)
  })

  it('dispatches to the chosen probe and refuses to dispatch without one', async () => {
    const state = await mount(() => useScanProfiles())
    state.openRun(profile({ id: 4 }))
    expect(state.runDialog.value).toBe(true)
    expect(state.runProbeId.value).toBe(12)
    await state.dispatch()
    expect(scanProfiles.runScanProfile).toHaveBeenCalledWith(4, 12)
    expect(state.runDialog.value).toBe(false)

    state.runProbeId.value = null
    await state.dispatch()
    expect(scanProfiles.runScanProfile).toHaveBeenCalledTimes(1)
  })

  it('shows the server reason when a probe refuses the job', async () => {
    const state = await mount(() => useScanProfiles())
    vi.mocked(scanProfiles.runScanProfile).mockRejectedValue(new Error('探针正忙'))
    state.openRun(profile({ id: 4 }))
    await state.dispatch()
    expect(ElMessage.error).toHaveBeenCalledWith('探针正忙')
    expect(state.runDialog.value).toBe(true)
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(scanProfiles.listScanProfiles).mockRejectedValue(new Error('配置服务不可用'))
    const state = await mount(() => useScanProfiles())
    expect(state.error.value).toBe('配置服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.profiles.value).toEqual([])
  })
})

describe('rule version console state', () => {
  it('loads the active rule set with its versions and the probe list', async () => {
    const state = await mount(() => useRuleVersions())
    expect(ruleSets.listRuleSets).toHaveBeenCalledWith()
    expect(ruleSets.listRuleSetVersions).toHaveBeenCalledWith(7)
    expect(probes.listProbes).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(state.ruleSet.value?.id).toBe(7)
    expect(state.activeVersion.value?.version).toBe('rel-2')
    expect(state.versions.value.map((item) => item.version)).toEqual(['rel-2', 'rel-1'])
    expect(state.loading.value).toBe(false)
  })

  it('clears the versions when the rule set is not initialised', async () => {
    vi.mocked(ruleSets.listRuleSets).mockResolvedValue({ items: [], total: 0 })
    const state = await mount(() => useRuleVersions())
    expect(state.ruleSet.value).toBeNull()
    expect(state.versions.value).toEqual([])
    expect(state.probes.value).toEqual([])
    expect(ruleSets.listRuleSetVersions).not.toHaveBeenCalled()
    expect(state.loading.value).toBe(false)
  })

  it('classifies probes by the version they report, not by what was published', async () => {
    vi.mocked(probes.listProbes).mockResolvedValue({
      items: [
        probe(1, { current_ruleset_version: 'rel-2' }),
        probe(2, { current_ruleset_version: 'rel-1' }),
        probe(3, { current_ruleset_version: 'rel-2', ruleset_last_error: '下载超时' }),
        probe(4, {}),
      ],
      total: 4, page: 1, page_size: 200,
    })
    const state = await mount(() => useRuleVersions())
    expect(state.probedVersion(state.probes.value[0])).toBe('rel-2')
    expect(state.probedVersion(state.probes.value[3])).toBe('')
    expect(state.syncedProbes.value.map((item) => item.id)).toEqual([1, 2, 3])
    expect(state.outOfDateProbes.value.map((item) => item.id)).toEqual([2])
    expect(state.failedProbes.value.map((item) => item.id)).toEqual([3])
  })

  it('stamps a version number for a new publish, posts it and reloads', async () => {
    const state = await mount(() => useRuleVersions())
    state.openPublish()
    expect(state.dialog.value).toBe(true)
    expect(state.draft.version).toMatch(/^rel-\d{12}$/)
    expect(state.draft.changelog).toBe('')

    state.draft.changelog = '新增邮箱规则'
    state.draft.min_agent_version = '3.5.0'
    const stamp = state.draft.version
    await state.publish()
    expect(ruleSets.publishRuleSetVersion).toHaveBeenCalledWith(7, {
      version: stamp, changelog: '新增邮箱规则', min_agent_version: '3.5.0',
    })
    expect(state.dialog.value).toBe(false)
    expect(state.saving.value).toBe(false)
    expect(ruleSets.listRuleSets).toHaveBeenCalledTimes(2)
    expect(ElMessage.success).toHaveBeenCalled()
  })

  it('shows the server reason when a publish is refused', async () => {
    const state = await mount(() => useRuleVersions())
    vi.mocked(ruleSets.publishRuleSetVersion).mockRejectedValue(new Error('版本号已存在'))
    state.openPublish()
    await state.publish()
    expect(ElMessage.error).toHaveBeenCalledWith('版本号已存在')
    expect(state.dialog.value).toBe(true)
    expect(state.saving.value).toBe(false)
  })

  it('rolls back by publishing the old version as a new one', async () => {
    const state = await mount(() => useRuleVersions())
    await state.rollback(version({ id: 1, version: 'rel-1' }))
    expect(ruleSets.rollbackRuleSetVersion).toHaveBeenCalledWith(7, {
      to_version: 'rel-1', changelog: '回滚到 rel-1',
    })
    expect(ElMessage.success).toHaveBeenCalled()
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(ruleSets.listRuleSets).mockRejectedValue(new Error('规则服务不可用'))
    const state = await mount(() => useRuleVersions())
    expect(state.error.value).toBe('规则服务不可用')
    expect(state.loading.value).toBe(false)
    expect(state.versions.value).toEqual([])
  })
})
