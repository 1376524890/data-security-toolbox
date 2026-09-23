import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useCryptoAssessmentResults, profilesOf, toRow } from '../modules/data-security/composables/useCryptoAssessmentResults'
import type { Task } from '../types/task'

const listTasks = vi.fn()
vi.mock('../api/tasks', () => ({ listTasks: (...args: unknown[]) => listTasks(...args) }))

beforeEach(() => {
  listTasks.mockReset()
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

  it('selects the first row so the panel has something to assess', async () => {
    listTasks.mockResolvedValue({ items: [task(1), task(2)], total: 2, page: 1, page_size: 20 })
    const state = useCryptoAssessmentResults()

    await state.load()

    expect(state.selectedId.value).toBe(1)
    expect(Object.keys(state.selectedProfiles.value)).toEqual(['10.0.0.9'])
  })

  it('drops a selection that fell off the page', async () => {
    listTasks.mockResolvedValueOnce({ items: [task(7)], total: 2, page: 1, page_size: 20 })
    const state = useCryptoAssessmentResults()
    await state.load()
    expect(state.selectedId.value).toBe(7)

    listTasks.mockResolvedValueOnce({ items: [task(8)], total: 2, page: 2, page_size: 20 })
    await state.setPage(2)

    expect(state.selectedId.value).toBe(8)
    expect(state.selected.value?.id).toBe(8)
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
