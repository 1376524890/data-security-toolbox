import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { computed, createApp, defineComponent, nextTick, ref, type App } from 'vue'
import { useDataTypeCenter } from '../modules/data-security/composables/useDataTypeCenter'
import { useDataTypeDetail } from '../modules/data-security/composables/useDataTypeDetail'
import type { DataObjectRow, DataTypeRow } from '../api/dataCatalog'
import * as catalog from '../api/dataCatalog'

vi.mock('../api/dataCatalog', () => ({
  listDataTypes: vi.fn(), getSensitivityLevels: vi.fn(), getDataType: vi.fn(),
}))

const typeRow = (category: string, entity: string, overrides: Partial<DataTypeRow> = {}): DataTypeRow => ({
  category, entity, level: 'L3', level_name: '敏感', level_description: '', severity: 'High',
  protected: true, source: 'builtin_default', field_only: false, object_count: 4,
  active_instance_count: 5, host_count: 2, confirmed_duplicate_count: 1, candidate_count: 2,
  candidate_duplicate_count: 2, identity_pending_count: 3, truncated: false, ...overrides,
})

const objectRow = (id: number, overrides: Partial<DataObjectRow> = {}): DataObjectRow => ({
  id, object_key: 'sha256:' + 'a'.repeat(64), object_type: 'file',
  content_hash: 'a'.repeat(64), hash_type: 'sha256', partial_version: '',
  identity_kind: 'confirmed', identity_confidence: 100, active_instance_count: 2,
  instance_count: 3, size: 1200, categories: ['email'], level: 'L3', level_source: 'builtin_default',
  sensitivity: 'High', first_seen_at: '2026-09-18T10:00:00', last_seen_at: '2026-09-19T10:00:00',
  ...overrides,
})

const totals = {
  types: 2, objects: 9, instances: 11, hosts: 3, confirmed_duplicates: 1,
  candidate_duplicates: 2, identity_pending: 4, truncated: false,
}

const levels = {
  levels: { L3: { name: '敏感', description: '需要保护' } },
  items: [], non_protected: [], note: '分级说明', source: 'builtin',
}

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
  vi.mocked(catalog.listDataTypes).mockResolvedValue({
    items: [typeRow('email', 'EMAIL'), typeRow('phone', 'PHONE_NUMBER')],
    count: 2, totals, totals_scope: 'all_probes', dedup_rules: {}, levels: {},
    mapping_source: 'builtin_default',
  })
  vi.mocked(catalog.getSensitivityLevels).mockResolvedValue(levels as any)
  vi.mocked(catalog.getDataType).mockImplementation((category: string) => Promise.resolve({
    ...typeRow(category, 'EMAIL'),
    objects: { items: [objectRow(11)], total: 41, page: 1, page_size: 20 },
  }))
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
})

describe('data type centre state', () => {
  it('loads the rows and the levels and keeps the server totals and scope', async () => {
    const state = await mount(useDataTypeCenter)
    expect(catalog.listDataTypes).toHaveBeenCalledOnce()
    expect(catalog.getSensitivityLevels).toHaveBeenCalledOnce()
    expect(state.rows.value?.items.map((item) => item.category)).toEqual(['email', 'phone'])
    expect(state.totals.value).toEqual(totals)
    expect(state.scopeLabel.value).toBe('全部探针')
    expect(state.loading.value).toBe(false)
  })

  it('filters on the category and on the entity name without recomputing totals', async () => {
    const state = await mount(useDataTypeCenter)
    state.search.value = 'MAIL'
    expect(state.filtered.value.map((item) => item.category)).toEqual(['email'])
    state.search.value = 'phone_number'
    expect(state.filtered.value.map((item) => item.category)).toEqual(['phone'])
    expect(state.totals.value.objects).toBe(9)
  })

  it('labels a per-probe scope and keeps a failed listing in the page state', async () => {
    vi.mocked(catalog.listDataTypes).mockResolvedValue({
      items: [], count: 0, totals, totals_scope: 'probe:12', dedup_rules: {}, levels: {},
      mapping_source: 'settings_override',
    })
    const state = await mount(useDataTypeCenter)
    expect(state.scopeLabel.value).toBe('探针 12')

    vi.mocked(catalog.listDataTypes).mockRejectedValue(new Error('后端不可用'))
    await state.load()
    expect(state.error.value).toBe('后端不可用')
    expect(state.loading.value).toBe(false)
    // A failed refresh keeps the last successful rows on screen rather than
    // pretending the scope is empty.
    expect(state.scopeLabel.value).toBe('探针 12')
    expect(state.rows.value?.totals_scope).toBe('probe:12')
  })
})

describe('data type detail state', () => {
  it('loads the type and its object page for the route category', async () => {
    const source = ref('email')
    const category = computed(() => source.value)
    const state = await mount(() => useDataTypeDetail(category))
    expect(catalog.getDataType).toHaveBeenCalledWith('email', { page: 1, page_size: 20 })
    expect(state.row.value?.category).toBe('email')
    expect(state.objects.value.map((item) => item.id)).toEqual([11])
    expect(state.total.value).toBe(41)
    expect(state.page.value).toBe(1)
  })

  it('requeries when the pager moves or the route category changes', async () => {
    const source = ref('email')
    const category = computed(() => source.value)
    const state = await mount(() => useDataTypeDetail(category))
    state.setPage(3)
    await flushing()
    expect(catalog.getDataType).toHaveBeenLastCalledWith('email', { page: 3, page_size: 20 })
    expect(state.page.value).toBe(3)

    source.value = 'phone'
    await flushing()
    expect(catalog.getDataType).toHaveBeenLastCalledWith('phone', { page: 3, page_size: 20 })
  })

  it('keeps a partial fingerprint on a lone instance as an unresolved identity', async () => {
    const source = ref('email')
    const category = computed(() => source.value)
    const state = await mount(() => useDataTypeDetail(category))
    expect(state.identityTag(objectRow(1, { identity_kind: 'confirmed', identity_confidence: 100 })))
      .toEqual({ text: '内容一致 100', type: 'success' })
    expect(state.identityTag(objectRow(2, { identity_kind: 'candidate', identity_confidence: 90, active_instance_count: 2 })))
      .toEqual({ text: '疑似副本 90', type: 'warning' })
    expect(state.identityTag(objectRow(3, { identity_kind: 'candidate', identity_confidence: 90, active_instance_count: 1 })))
      .toEqual({ text: '待确认身份 90', type: 'warning' })
    expect(state.identityTag(objectRow(4, { identity_kind: 'scoped' })))
      .toEqual({ text: '作用域内标识', type: 'info' })
  })

  it('keeps a failed load in the page state', async () => {
    vi.mocked(catalog.getDataType).mockRejectedValue(new Error('类型不存在'))
    const state = await mount(() => useDataTypeDetail(computed(() => 'missing')))
    expect(state.error.value).toBe('类型不存在')
    expect(state.loading.value).toBe(false)
    expect(state.row.value).toBeNull()
  })
})
