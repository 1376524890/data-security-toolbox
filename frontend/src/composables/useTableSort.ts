import { reactive } from 'vue'

/** What Element Plus hands to `@sort-change`. */
export interface TableSortChange {
  prop: string | null
  order: 'ascending' | 'descending' | null
}

export type SortOrder = 'ascending' | 'descending' | null

/**
 * Column sorting shared by every list page.
 *
 * Element Plus column headers carry `sortable="custom"`; this composable turns
 * the emitted `{ prop, order }` into the one `order_by` spelling the list APIs
 * accept (`field` ascending, `-field` descending) and asks the page to reload
 * from page 1 — a sort that left the page number alone would show rows from a
 * page that no longer exists under the new order.
 *
 * Client-side lists (data the page already holds in full) use the same state and
 * only skip the reload callback.
 */
export function useTableSort(onChange?: () => void, defaults: { prop?: string; order?: SortOrder } = {}) {
  const sort = reactive<{ prop: string; order: SortOrder }>({
    prop: defaults.prop ?? '',
    order: defaults.order ?? null,
  })

  function onSortChange({ prop, order }: TableSortChange): void {
    sort.prop = order && prop ? prop : ''
    sort.order = order ?? null
    onChange?.()
  }

  /** The `order_by` query value, or `undefined` when the list is unsorted. */
  function orderBy(): string | undefined {
    if (!sort.prop || !sort.order) return undefined
    return `${sort.order === 'descending' ? '-' : ''}${sort.prop}`
  }

  /** Which direction a header should render as active, for non-Element tables. */
  function direction(prop: string): SortOrder {
    return sort.prop === prop ? sort.order : null
  }

  return { sort, onSortChange, orderBy, direction }
}

/**
 * Client-side sort for a list the page already holds in full.
 *
 * Sorted copies are returned rather than mutating the source array: the
 * unsorted order is the server's, and a page that overwrote it could not get it
 * back without another request.
 */
export function sortRows<T>(rows: T[], prop: string, order: SortOrder,
                           value: (row: T, prop: string) => unknown): T[] {
  if (!prop || !order) return rows
  const sign = order === 'descending' ? -1 : 1
  return [...rows].sort((left, right) => {
    const a = value(left, prop)
    const b = value(right, prop)
    if (a == null && b == null) return 0
    if (a == null) return 1
    if (b == null) return -1
    if (typeof a === 'number' && typeof b === 'number') return (a - b) * sign
    return String(a).localeCompare(String(b), 'zh-CN') * sign
  })
}
