import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useAutoRefresh } from '../composables/useAutoRefresh'
import { sortRows, useTableSort } from '../composables/useTableSort'

function deferred<T = void>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => { resolve = r })
  return { promise, resolve }
}

describe('useAutoRefresh', () => {
  beforeEach(() => { vi.useFakeTimers() })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('ticks on the interval, always as a silent refresh', async () => {
    const load = vi.fn().mockResolvedValue(undefined)
    const timer = useAutoRefresh(load, { intervalMs: 1000 })
    timer.start()
    await vi.advanceTimersByTimeAsync(3000)
    expect(load).toHaveBeenCalledTimes(3)
    expect(load).toHaveBeenCalledWith({ silent: true })
    timer.stop()
  })

  it('never stacks a second tick while the previous one is still running', async () => {
    const gate = deferred()
    const load = vi.fn().mockReturnValue(gate.promise)
    const timer = useAutoRefresh(load, { intervalMs: 1000 })
    timer.start()
    await vi.advanceTimersByTimeAsync(5000)
    // Five intervals elapsed, but the first request has not answered: a slow
    // endpoint must not become five requests the moment it is unwell.
    expect(load).toHaveBeenCalledTimes(1)
    gate.resolve()
    await vi.advanceTimersByTimeAsync(1000)
    expect(load).toHaveBeenCalledTimes(2)
    timer.stop()
  })

  it('does not poll a hidden tab', async () => {
    const hidden = vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)
    const load = vi.fn().mockResolvedValue(undefined)
    const timer = useAutoRefresh(load, { intervalMs: 1000 })
    timer.start()
    await vi.advanceTimersByTimeAsync(3000)
    expect(load).not.toHaveBeenCalled()
    hidden.mockReturnValue(false)
    await vi.advanceTimersByTimeAsync(1000)
    expect(load).toHaveBeenCalledTimes(1)
    timer.stop()
    hidden.mockRestore()
  })

  it('reports a failing tick instead of letting it reject', async () => {
    const onError = vi.fn()
    const load = vi.fn().mockRejectedValue(new Error('boom'))
    const timer = useAutoRefresh(load, { intervalMs: 1000, onError })
    timer.start()
    await vi.advanceTimersByTimeAsync(1000)
    expect(onError).toHaveBeenCalledTimes(1)
    timer.stop()
  })

  it('a manual refreshNow still guards against an in-flight load', async () => {
    const gate = deferred()
    const load = vi.fn().mockReturnValue(gate.promise)
    const timer = useAutoRefresh(load, { intervalMs: 0 })
    void timer.refreshNow()
    await timer.refreshNow()
    expect(load).toHaveBeenCalledTimes(1)
    gate.resolve()
  })

  it('stop clears the timer', async () => {
    const load = vi.fn().mockResolvedValue(undefined)
    const timer = useAutoRefresh(load, { intervalMs: 1000 })
    timer.start()
    timer.stop()
    await vi.advanceTimersByTimeAsync(5000)
    expect(load).not.toHaveBeenCalled()
  })
})

describe('useTableSort', () => {
  it('turns a header change into the API order_by spelling', () => {
    const onChange = vi.fn()
    const table = useTableSort(onChange)
    table.onSortChange({ prop: 'name', order: 'ascending' })
    expect(table.orderBy()).toBe('name')
    table.onSortChange({ prop: 'name', order: 'descending' })
    expect(table.orderBy()).toBe('-name')
    expect(onChange).toHaveBeenCalledTimes(2)
  })

  it('clearing a sort returns to the endpoint default', () => {
    const table = useTableSort()
    table.onSortChange({ prop: 'name', order: 'ascending' })
    table.onSortChange({ prop: 'name', order: null })
    expect(table.orderBy()).toBeUndefined()
    expect(table.sort.prop).toBe('')
  })

  it('ignores a prop Element Plus sends without a direction', () => {
    const table = useTableSort()
    table.onSortChange({ prop: 'name', order: null })
    expect(table.sort.prop).toBe('')
  })

  it('exposes the active direction for a non-Element header', () => {
    const table = useTableSort()
    table.onSortChange({ prop: 'size', order: 'descending' })
    expect(table.direction('size')).toBe('descending')
    expect(table.direction('name')).toBeNull()
  })
})

describe('sortRows', () => {
  interface Row { size: number | null; name: string }
  const value = (row: Row, prop: string): unknown => (row as unknown as Record<string, unknown>)[prop]

  it('sorts numbers numerically, not as text', () => {
    const rows: Row[] = [{ size: 9, name: 'b' }, { size: 100, name: 'a' }]
    expect(sortRows(rows, 'size', 'ascending', value).map((row) => row.size)).toEqual([9, 100])
  })

  it('sorts strings as Chinese locale text', () => {
    const rows: Row[] = [{ size: 1, name: '乙' }, { size: 2, name: '甲' }]
    expect(sortRows(rows, 'name', 'ascending', value)[0].name).toBe('甲')
  })

  it('keeps missing values last in both directions', () => {
    const rows: Row[] = [{ size: null, name: 'z' }, { size: 2, name: 'b' }, { size: 1, name: 'a' }]
    expect(sortRows(rows, 'size', 'ascending', value).map((row) => row.size)).toEqual([1, 2, null])
    expect(sortRows(rows, 'size', 'descending', value).map((row) => row.size)).toEqual([2, 1, null])
  })

  it('sorts a copy and leaves the server order untouched', () => {
    const rows: Row[] = [{ size: 2, name: 'b' }, { size: 1, name: 'a' }]
    const sorted = sortRows(rows, 'size', 'ascending', value)
    expect(sorted).not.toBe(rows)
    expect(sorted.map((row) => row.size)).toEqual([1, 2])
    expect(rows.map((row) => row.size)).toEqual([2, 1])
  })

  it('returns the rows unchanged when no column is sorted', () => {
    const rows: Row[] = [{ size: 2, name: 'b' }, { size: 1, name: 'a' }]
    expect(sortRows(rows, '', null, value)).toEqual(rows)
  })
})
