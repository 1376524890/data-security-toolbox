/**
 * Asset-catalogue state.
 *
 * The page is one table over every collector: what it shows must be exactly what
 * the server returned for the current filters, with no client-side filtering that
 * would hide rows the operator asked for.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, ref, type App, type Ref } from 'vue'
import { useAssetInventory } from '../modules/data-security/composables/useAssetInventory'
import type { AssetInstanceRow } from '../api/dataCatalog'
import * as api from '../api/dataCatalog'

vi.mock('../api/dataCatalog', () => ({ listAssetInstances: vi.fn() }))

const row = (overrides: Partial<AssetInstanceRow> = {}): AssetInstanceRow => ({
  id: 12, object_id: 3, probe_id: 0, source_kind: 'file_share', owner_key: 'file-source:4',
  probe_name: '', host: '192.168.191.130', path: '/srv/ftp/contacts.csv', name: 'contacts.csv',
  instance_type: 'file', size: 4888, content_hash: 'abc', hash_type: 'scoped', status: 'ACTIVE',
  owner: '', group: '', permission: '', sensitivity: 'High', level: 'L3', level_source: '',
  categories: ['phone'], coverage: 'complete', termination_reason: 'complete',
  ruleset_version: '2026.09', engine_version: '1.0.0', profile_version: '1',
  last_scan_id: '5079', first_seen_at: '2026-09-20T07:20:16Z', last_seen_at: '2026-09-20T07:20:16Z',
  ...overrides,
})

const page = (items: AssetInstanceRow[], total = items.length) => ({
  items, total, page: 1, page_size: 50,
})

let app: App | undefined

const mountState = async (sensitive: boolean, owner: Ref<string>) => {
  let state!: ReturnType<typeof useAssetInventory>
  const Harness = defineComponent({
    setup() {
      state = useAssetInventory(sensitive, owner)
      return () => null
    },
  })
  app = createApp(Harness)
  app.mount(document.createElement('div'))
  await flushing()
  return state
}

const flushing = async () => {
  for (let index = 0; index < 4; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

afterEach(() => {
  app?.unmount()
  app = undefined
  vi.clearAllMocks()
})

describe('asset inventory', () => {
  it('loads every active asset by default, newest first', async () => {
    vi.mocked(api.listAssetInstances).mockResolvedValue(page([row()]))
    const state = await mountState(false, ref(''))
    expect(api.listAssetInstances).toHaveBeenCalledWith({
      page: 1, page_size: 50, search: undefined, source_kind: undefined, status: 'ACTIVE',
      sensitive_only: false, owner_key: undefined, order_by: '-last_seen_at',
    })
    expect(state.rows.value.map((item) => item.name)).toEqual(['contacts.csv'])
    expect(state.total.value).toBe(1)
    expect(state.error.value).toBe('')
  })

  it('asks for sensitive hits only when the page is the sensitive view', async () => {
    vi.mocked(api.listAssetInstances).mockResolvedValue(page([row()]))
    await mountState(true, ref(''))
    expect(vi.mocked(api.listAssetInstances).mock.calls[0][0]).toMatchObject({ sensitive_only: true })
  })

  it('scopes the request to one collector and reloads when that scope changes', async () => {
    vi.mocked(api.listAssetInstances).mockResolvedValue(page([row()]))
    const owner = ref('file-source:4')
    await mountState(false, owner)
    expect(vi.mocked(api.listAssetInstances).mock.calls[0][0]).toMatchObject({ owner_key: 'file-source:4' })
    owner.value = 'db:7'
    await flushing()
    expect(api.listAssetInstances).toHaveBeenCalledTimes(2)
    expect(vi.mocked(api.listAssetInstances).mock.calls[1][0]).toMatchObject({ owner_key: 'db:7' })
    expect(api.listAssetInstances).toHaveBeenLastCalledWith(expect.objectContaining({ page: 1 }))
  })

  it('passes the operator filters and the selected page through', async () => {
    vi.mocked(api.listAssetInstances).mockResolvedValue(page([row()]))
    const state = await mountState(false, ref(''))
    state.search.value = 'customer'
    state.source.value = 'database'
    state.status.value = ''
    state.load(4)
    await flushing()
    expect(api.listAssetInstances).toHaveBeenLastCalledWith(expect.objectContaining({
      page: 4, search: 'customer', source_kind: 'database', status: undefined,
    }))
    expect(state.page.value).toBe(4)
  })

  it('reports a failed listing instead of showing the previous rows as current', async () => {
    vi.mocked(api.listAssetInstances).mockRejectedValue(new Error('500 server error'))
    const state = await mountState(false, ref(''))
    expect(state.error.value).toContain('500')
    expect(state.rows.value).toEqual([])
    expect(state.loading.value).toBe(false)
  })

  it('keeps the answer that belongs to the latest request', async () => {
    let release: (value: unknown) => void = () => undefined
    const pending = new Promise((resolve) => { release = resolve })
    vi.mocked(api.listAssetInstances).mockReturnValueOnce(pending as never)
    vi.mocked(api.listAssetInstances).mockResolvedValueOnce(page([row({ id: 99, name: 'newer.csv' })]))
    const state = await mountState(false, ref(''))
    state.load(1)
    await flushing()
    release(page([row({ id: 12, name: 'stale.csv' })]))
    await flushing()
    expect(state.rows.value.map((item) => item.name)).toEqual(['newer.csv'])
  })
})
