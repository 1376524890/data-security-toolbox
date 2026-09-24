import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useCryptoAssessmentResults, profilesOf, toRow, toAssetRows } from '../modules/data-security/composables/useCryptoAssessmentResults'
import { weakCryptoConfig } from '../modules/tasks/assessment/cryptoAssessment'
import type { CryptoProfileLike } from '../modules/tasks/assessment/composables/useCryptoAssessment'
import type { Task } from '../types/task'

const listTasks = vi.fn()
vi.mock('../api/tasks', () => ({ listTasks: (...args: unknown[]) => listTasks(...args) }))

beforeEach(() => {
  listTasks.mockReset()
})

// The shipped weak preset: an observation that must not come back a pass.
const weakProfile = (): CryptoProfileLike => ({
  config: {
    algorithms: weakCryptoConfig.algorithms,
    cipherSuites: weakCryptoConfig.cipherSuites,
    protocols: weakCryptoConfig.protocols,
    keyLengths: weakCryptoConfig.keyLengths,
    keyManagement: weakCryptoConfig.keyManagement,
  },
})

function task(id: number, overrides: Partial<Task> = {}): Task {
  return {
    id,
    kind: 'scan',
    status: 'Success',
    progress: 100,
    current_stage: '',
    log: '',
    payload: { target: '10.0.0.9', crypto_assess: true },
    result: {
      crypto_profiles: { '10.0.0.9': { config: { algorithms: ['SM4'] } } },
      crypto_profile_hosts: 1,
    },
    error: '',
    created_at: '2026-09-23T10:00:00Z',
    finished_at: '2026-09-23T10:05:00Z',
    ...overrides,
  } as Task
}

describe('crypto assessment results state', () => {
  it('lists the tasks that actually carry a profile', async () => {
    listTasks.mockResolvedValue({
      items: [
        task(1355),
        // Ran without 密码评估 -> no result block: not an assessment.
        task(1019, { payload: { target: '10.0.0.9' }, result: {} }),
        // Ticked but cancelled before it observed anything.
        task(1354, { status: 'Partial', result: {} }),
      ],
      total: 3,
      page: 1,
      page_size: 20,
    })
    const state = useCryptoAssessmentResults()

    await state.load()

    expect(listTasks).toHaveBeenCalledWith({ kind: 'scan', page: 1, page_size: 20 })
    expect(state.rows.value.map((row) => row.id)).toEqual([1355])
    // The server's count is kept, so the page never implies a smaller inventory
    // than exists just because the filter is applied here.
    expect(state.taskTotal.value).toBe(3)
  })

  it('opens on the first asset, so the panel always has a standing result', async () => {
    listTasks.mockResolvedValue({ items: [task(1), task(2)], total: 2, page: 1, page_size: 20 })
    const state = useCryptoAssessmentResults()

    await state.load()

    // The asset view is the standing one, so it is what the page opens on —
    // not a task the operator would have to remember the id of.
    expect(state.selectedHost.value).toBe('10.0.0.9')
    expect(Object.keys(state.panelProfiles.value)).toEqual(['10.0.0.9'])
    expect(state.selectedId.value).toBeNull()
  })

  it('folds task rows into one standing row per host, newest observation winning', () => {
    const older = toRow(task(1, { finished_at: '2026-09-21T10:00:00Z' }))!
    const newer = toRow(task(2, {
      finished_at: '2026-09-23T10:00:00Z',
      result: { crypto_profiles: { '10.0.0.9': weakProfile() } },
    }))!

    // Input order must not matter: the observation time decides.
    for (const rows of [[newer, older], [older, newer]]) {
      const assets = toAssetRows(rows)
      expect(assets).toHaveLength(1)
      expect(assets[0].host).toBe('10.0.0.9')
      expect(assets[0].taskId).toBe(2)
      expect(assets[0].profile.config.algorithms).toEqual(weakCryptoConfig.algorithms)
      // The row carries the verdict, not just the facts: the older observation
      // passed, the newer one does not, and the asset shows where it stands now.
      expect(assets[0].level).not.toBe('合规')
      expect(assets[0].observedAt).toBe('2026-09-23T10:00:00Z')
    }
    expect(toAssetRows([older])[0].level).toBe('合规')
  })

  it('keeps every host of one task as its own asset row', () => {
    const row = toRow(task(3, {
      result: {
        crypto_profiles: {
          '10.0.0.9': { config: { algorithms: ['SM4'] } },
          '10.0.0.20': weakProfile(),
        },
      },
    }))!
    const assets = toAssetRows([row])
    expect(assets.map((item) => item.host).sort()).toEqual(['10.0.0.20', '10.0.0.9'])
    const byHost = Object.fromEntries(assets.map((item) => [item.host, item.level]))
    expect(byHost['10.0.0.9']).toBe('合规')
    expect(byHost['10.0.0.20']).not.toBe('合规')
  })

  it('filters and sorts the standing rows by verdict, not by spelling', async () => {
    listTasks.mockResolvedValue({
      items: [
        task(1, { finished_at: '2026-09-22T10:00:00Z' }),
        task(2, {
          payload: { target: '10.0.0.20', crypto_assess: true },
          finished_at: '2026-09-23T10:00:00Z',
          result: { crypto_profiles: { '10.0.0.20': weakProfile() } },
        }),
      ],
      total: 2, page: 1, page_size: 20,
    })
    const state = useCryptoAssessmentResults()
    await state.load()

    // Newest observation first is the natural reading order.
    expect(state.assets.value.map((item) => item.host)).toEqual(['10.0.0.20', '10.0.0.9'])
    expect(state.assetTotal.value).toBe(2)

    // The weak observation must not read as a pass, or this test asserts nothing.
    const weakLevel = state.assets.value[0].level
    expect(weakLevel).not.toBe('合规')

    state.assetFilters.search = '10.0.0.9'
    expect(state.visibleAssets.value.map((item) => item.host)).toEqual(['10.0.0.9'])
    state.assetFilters.search = weakLevel
    expect(state.visibleAssets.value.map((item) => item.host)).toEqual(['10.0.0.20'])
    state.assetFilters.search = ''
    expect(state.visibleAssets.value).toHaveLength(2)

    // 等级 is a verdict: rank order (worst first) rather than 拼音 order.
    state.assetTable.onSortChange({ prop: 'level', order: 'ascending' })
    expect(state.visibleAssets.value.map((item) => item.host)).toEqual(['10.0.0.20', '10.0.0.9'])
    state.assetTable.onSortChange({ prop: 'overallScore', order: 'descending' })
    expect(state.visibleAssets.value[0].host).toBe('10.0.0.9')
  })

  it('picking an asset and picking a task are mutually exclusive', async () => {
    listTasks.mockResolvedValue({ items: [task(1)], total: 1, page: 1, page_size: 20 })
    const state = useCryptoAssessmentResults()
    await state.load()

    state.selectAsset('10.0.0.9')
    expect(state.selectedHost.value).toBe('10.0.0.9')
    expect(state.selectedId.value).toBeNull()

    // The task side (what the page's row click does) clears the asset pick.
    state.selectedId.value = 1
    state.selectedHost.value = ''
    expect(state.selectedHost.value).toBe('')
    expect(Object.keys(state.panelProfiles.value)).toEqual(['10.0.0.9'])
  })

  it('drops a task selection that fell off the page and hands the panel back', async () => {
    listTasks.mockResolvedValueOnce({ items: [task(7)], total: 2, page: 1, page_size: 20 })
    const state = useCryptoAssessmentResults()
    await state.load()
    state.selectedId.value = 7
    state.selectedHost.value = ''

    listTasks.mockResolvedValueOnce({ items: [task(8)], total: 2, page: 2, page_size: 20 })
    await state.setPage(2)

    // The task is not on this page any more, so the task side clears...
    expect(state.selectedId.value).toBeNull()
    expect(state.selected.value).toBeNull()
    // ...and the standing asset view takes the panel back.
    expect(state.selectedHost.value).toBe('10.0.0.9')
  })

  it('reports an empty page without inventing rows', async () => {
    listTasks.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
    const state = useCryptoAssessmentResults()

    await state.load()

    expect(state.rows.value).toEqual([])
    expect(state.selected.value).toBeNull()
    expect(state.error.value).toBe('')
  })

  it('keeps the failure message instead of showing a false empty list', async () => {
    listTasks.mockRejectedValue(new Error('boom'))
    const state = useCryptoAssessmentResults()

    await state.load()

    expect(state.error.value).toContain('boom')
    expect(state.loading.value).toBe(false)
  })

  it('never counts a task whose result is missing or null', () => {
    expect(profilesOf(task(1, { result: null as never }))).toEqual({})
    expect(toRow(task(1, { result: null as never }))).toBeNull()
    expect(toRow(task(2, { result: { crypto_profiles: {} } }))).toBeNull()
  })
})
