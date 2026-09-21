/**
 * Target-database collection state.
 *
 * Two contracts matter more than the plumbing: the password is write-only (sent
 * once, never read back) and a scan is only ever reported from the server task,
 * so the state must never invent progress.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick, type App } from 'vue'
import { ElMessage } from 'element-plus'
import { useDatabaseConnections } from '../modules/collection/composables/useDatabaseConnections'
import type { ConnectionDetail, DatabaseConnection, ScanSummary } from '../api/databaseConnections'
import * as api from '../api/databaseConnections'

vi.mock('../api/databaseConnections', () => ({
  listDatabaseConnections: vi.fn(), createDatabaseConnection: vi.fn(),
  getDatabaseConnection: vi.fn(), updateDatabaseConnection: vi.fn(),
  deleteDatabaseConnection: vi.fn(), testDatabaseConnection: vi.fn(),
  listConnectionSchemas: vi.fn(), listConnectionTables: vi.fn(),
  startDatabaseScan: vi.fn(), listConnectionScans: vi.fn(), getScanDetail: vi.fn(),
}))
vi.mock('element-plus', () => ({ ElMessage: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const connection = (overrides: Partial<DatabaseConnection> = {}): DatabaseConnection => ({
  id: 3, name: 'kali-mariadb', engine: 'mysql', engine_label: 'MySQL / MariaDB',
  host: '192.168.191.130', port: 3306, database: 'dst_demo', username: 'dst_ro',
  password_set: true, tls_mode: '', options: {}, enabled: true,
  last_test_at: '', last_test_status: 'untested', last_test_error: '',
  last_scan_at: '', created_at: '', updated_at: '',
  ...overrides,
})

const scan = (taskId: number, overrides: Partial<ScanSummary> = {}): ScanSummary => ({
  task_id: taskId, status: 'Success', stage: '完成', progress: 100, error: '',
  created_at: '', started_at: '', finished_at: '', duration_seconds: 1.2,
  connection_id: 3, scope: { schemas: ['dst_demo'], tables: [] }, config_hash: 'abcd1234',
  server_version: '11.8.6-MariaDB', engine: 'mysql', host: '192.168.191.130', port: 3306,
  database: 'dst_demo', schemas: ['dst_demo'], tables_total: 9, tables_selected: 9,
  tables_scanned: 9, tables_failed: 0, rows_read: 120, values_scanned: 600, hits: 7,
  objects: 9, detections: 7, complete_scope: true, termination_reason: 'complete',
  read_only: true, categories: ['phone'], not_observed: 0,
  engine_version: '1.0.0', ruleset_version: '2026.09', sample_rows: 200, notes: [],
  ...overrides,
})

let state: ReturnType<typeof useDatabaseConnections>
let app: App | undefined
let host: HTMLElement | undefined

const flushing = async () => {
  for (let index = 0; index < 4; index += 1) {
    await Promise.resolve()
    await nextTick()
  }
}

const mountState = async () => {
  const Harness = defineComponent({
    setup() {
      state = useDatabaseConnections()
      return () => null
    },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(Harness)
  app.mount(host)
  await flushing()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  vi.mocked(api.listDatabaseConnections).mockResolvedValue({
    items: [connection()], total: 1, page: 1, page_size: 200,
    engines: [{ engine: 'mysql', label: 'MySQL / MariaDB', default_port: 3306 }], note: '平台直连',
  })
  vi.mocked(api.getDatabaseConnection).mockResolvedValue(
    { ...connection(), scans: [scan(41)] } as ConnectionDetail)
  vi.mocked(api.listConnectionScans).mockResolvedValue({ connection_id: 3, items: [scan(41)], count: 1 })
})

afterEach(() => {
  app?.unmount()
  host?.remove()
  app = undefined
  host = undefined
  vi.useRealTimers()
})

describe('database connection state', () => {
  it('loads the connections, keeps the engine catalogue and selects the first target', async () => {
    await mountState()
    expect(api.listDatabaseConnections).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(state.connections.value.map((row) => row.id)).toEqual([3])
    expect(state.engines.value[0].engine).toBe('mysql')
    expect(state.note.value).toBe('平台直连')
    expect(state.selectedId.value).toBe(3)
    await flushing()
    expect(api.getDatabaseConnection).toHaveBeenCalledWith(3)
    expect(state.detail.value?.scans.length).toBe(1)
    expect(state.loading.value).toBe(false)
    expect(state.error.value).toBe('')
  })

  it('sends a new password once on create and then forgets it locally', async () => {
    vi.mocked(api.createDatabaseConnection).mockResolvedValue(connection({ id: 9 }))
    await mountState()
    // The new target is part of the list the refresh reads back.
    vi.mocked(api.listDatabaseConnections).mockResolvedValue({
      items: [connection({ id: 3 }), connection({ id: 9, name: 'new-db' })],
      total: 2, page: 1, page_size: 200, engines: [], note: '',
    })
    state.openCreate()
    Object.assign(state.form, {
      name: 'new-db', engine: 'mysql', host: '10.0.0.5', port: 3306,
      database: 'shop', username: 'ro', password: 'secr3t', enabled: true,
    })
    await state.save()
    expect(api.createDatabaseConnection).toHaveBeenCalledWith(
      expect.objectContaining({ host: '10.0.0.5', database: 'shop', password: 'secr3t' }))
    expect(state.form.password).toBe('')
    expect(state.formOpen.value).toBe(false)
    expect(state.selectedId.value).toBe(9)
    expect(ElMessage.success).toHaveBeenCalled()
  })

  it('leaves the stored password alone when the edit form is submitted empty', async () => {
    vi.mocked(api.updateDatabaseConnection).mockResolvedValue(connection({ name: 'renamed' }))
    await mountState()
    state.openEdit(state.connections.value[0])
    state.form.name = 'renamed'
    await state.save()
    const body = vi.mocked(api.updateDatabaseConnection).mock.calls[0][1] as Record<string, unknown>
    expect(body.name).toBe('renamed')
    expect('password' in body).toBe(false)
  })

  it('refuses to save without a name or host instead of sending a half configuration', async () => {
    await mountState()
    state.openCreate()
    state.form.name = 'only-a-name'
    await state.save()
    expect(api.createDatabaseConnection).not.toHaveBeenCalled()
    expect(ElMessage.warning).toHaveBeenCalled()
  })

  it('reports the test outcome the server returned, not an assumption', async () => {
    vi.mocked(api.testDatabaseConnection).mockResolvedValue(
      { ...connection(), result: { status: 'ok', server_version: '11.8.6-MariaDB' } })
    await mountState()
    await state.test(state.connections.value[0])
    expect(ElMessage.success).toHaveBeenCalledWith(expect.stringContaining('11.8.6-MariaDB'))
    vi.mocked(api.testDatabaseConnection).mockResolvedValue(
      { ...connection(), result: { status: 'unreachable', error: 'connection refused' } })
    await state.test(state.connections.value[0])
    expect(ElMessage.error).toHaveBeenCalledWith(expect.stringContaining('connection refused'))
    expect(state.testing.value).toBeNull()
  })

  it('queues the picked tables qualified with the schema and clears nothing else', async () => {
    vi.mocked(api.startDatabaseScan).mockResolvedValue(
      { id: 77, status: 'Pending', location: 'platform', connection_id: 3, config_hash: 'abcd1234' })
    await mountState()
    state.schema.value = 'dst_demo'
    state.pickedTables.value = ['customers']
    state.toggleTable('payments')
    await state.start()
    expect(api.startDatabaseScan).toHaveBeenCalledWith(3, {
      schemas: ['dst_demo'], tables: ['dst_demo.customers', 'dst_demo.payments'],
    })
    expect(api.listConnectionScans).toHaveBeenCalledWith(3, 20)
    expect(state.dispatching.value).toBe(false)
  })

  it('reads the schema and table list from the target before anything is queued', async () => {
    vi.mocked(api.listConnectionSchemas).mockResolvedValue(
      { connection_id: 3, schemas: ['dst_demo', 'mysql'], count: 2, default: 'dst_demo' })
    vi.mocked(api.listConnectionTables).mockResolvedValue({
      schema: 'dst_demo', count: 2, tables: [
        { name: 'customers', kind: 'table', schema: 'dst_demo', columns: 6 },
        { name: 'order_view', kind: 'view', schema: 'dst_demo', columns: 3 },
      ],
    })
    await mountState()
    await state.loadScope()
    expect(state.schema.value).toBe('dst_demo')
    expect(state.tables.value.map((row) => row.name)).toEqual(['customers', 'order_view'])
    expect(state.confirmedTables.value).toBe(1)
  })

  it('opens the scan detail from the task the server recorded', async () => {
    vi.mocked(api.getScanDetail).mockResolvedValue(
      { id: 41, kind: 'database_scan', status: 'Success', progress: 100, current_stage: '完成',
        error: '', result: {}, summary: scan(41) })
    await mountState()
    await state.openScan(scan(41))
    expect(api.getScanDetail).toHaveBeenCalledWith(41)
    expect(state.scanDetail.value?.summary.hits).toBe(7)
    expect(state.scanOpen.value).toBe(true)
  })

  it('keeps the collected pages when a connection is removed and only drops the selection', async () => {
    vi.mocked(api.deleteDatabaseConnection).mockResolvedValue({ deleted: true, kept_instances: 9 })
    await mountState()
    // The deleted target is gone from the list the next call returns.
    vi.mocked(api.listDatabaseConnections).mockResolvedValue({
      items: [], total: 0, page: 1, page_size: 200, engines: [], note: '',
    })
    await state.remove(state.connections.value[0])
    expect(ElMessage.success).toHaveBeenCalledWith(expect.stringContaining('9'))
    expect(state.selectedId.value).toBeNull()
    expect(state.detail.value).toBeNull()
  })

  it('refreshes the scan history on the timer and stops when switched off', async () => {
    await mountState()
    await state.loadScans()
    expect(api.listConnectionScans).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(5000)
    await flushing()
    expect(api.listConnectionScans).toHaveBeenCalledTimes(2)
    state.autoRefresh.value = false
    await vi.advanceTimersByTimeAsync(5000)
    await flushing()
    expect(api.listConnectionScans).toHaveBeenCalledTimes(2)
  })

  it('labels target statuses and termination reasons honestly', async () => {
    await mountState()
    expect(state.testLabel('read_only_violation')).toBe('只读校验失败')
    expect(state.testLabel('')).toBe('—')
    expect(state.statusType('unreachable')).toBe('danger')
    expect(state.statusType('ok')).toBe('success')
    expect(state.reasonLabel('table_budget')).toBe('达到表数量上限')
    expect(state.reasonLabel('complete')).toBe('完整读取')
  })

  it('keeps a failed draft available and releases the save indicator', async () => {
    vi.mocked(api.updateDatabaseConnection).mockRejectedValueOnce(new Error('save failed'))
    await mountState()
    state.openEdit(state.connections.value[0])
    state.form.password = 'replacement'
    await state.save()
    expect(api.updateDatabaseConnection).toHaveBeenLastCalledWith(3,
      expect.objectContaining({ password: 'replacement' }))
    expect(state.formOpen.value).toBe(true)
    expect(state.form.password).toBe('replacement')
    expect(state.saving.value).toBe(false)
    expect(ElMessage.error).toHaveBeenCalledWith('save failed')
  })

  it('uses the newly selected connection for scope, dispatch and polling', async () => {
    const second = connection({ id: 8, database: 'shop' })
    vi.mocked(api.listDatabaseConnections).mockResolvedValue({
      items: [connection(), second], total: 2, page: 1, page_size: 200, engines: [], note: '',
    })
    vi.mocked(api.getDatabaseConnection).mockImplementation(async (id) => ({
      ...(id === 8 ? second : connection()), scans: [],
    }))
    vi.mocked(api.listConnectionSchemas).mockResolvedValueOnce({
      connection_id: 8, schemas: ['shop'], count: 1, default: 'shop',
    })
    vi.mocked(api.listConnectionTables).mockResolvedValueOnce({ schema: 'shop', tables: [], count: 0 })
    vi.mocked(api.startDatabaseScan).mockResolvedValueOnce({
      id: 78, status: 'Pending', location: 'platform', connection_id: 8, config_hash: 'hash',
    })
    vi.mocked(api.listConnectionScans).mockResolvedValue({ connection_id: 8, items: [], count: 0 })
    await mountState()
    state.pickedTables.value = ['old_selection']
    await state.select(second)
    expect(state.pickedTables.value).toEqual([])
    await state.loadScope()
    await state.start()
    expect(api.listConnectionSchemas).toHaveBeenCalledWith(8)
    expect(api.listConnectionTables).toHaveBeenCalledWith(8, 'shop')
    expect(api.startDatabaseScan).toHaveBeenCalledWith(8, { schemas: ['shop'], tables: [] })
    await vi.advanceTimersByTimeAsync(5000)
    expect(api.listConnectionScans).toHaveBeenLastCalledWith(8, 20)
    expect(state.detail.value?.id).toBe(8)
  })

  it('clears the scope list after a read failure without dispatching a scan', async () => {
    vi.mocked(api.listConnectionSchemas).mockRejectedValueOnce(new Error('scope failed'))
    await mountState()
    state.schemas.value = ['old']
    state.tables.value = [{ name: 'old', kind: 'table', schema: 'old', columns: 1 }]
    await state.loadScope()
    expect(state.schemas.value).toEqual([])
    expect(state.tables.value).toEqual([])
    expect(state.scopeLoading.value).toBe(false)
    expect(api.startDatabaseScan).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('scope failed')
  })

  it('keeps the last server history if its refresh fails', async () => {
    vi.mocked(api.listConnectionScans).mockRejectedValueOnce(new Error('history failed'))
    await mountState()
    await state.loadScans()
    expect(state.detail.value?.scans[0].task_id).toBe(41)
    expect(state.error.value).toBe('history failed')
  })

  it('stops polling after the page is unmounted', async () => {
    await mountState()
    app!.unmount()
    app = undefined
    await vi.advanceTimersByTimeAsync(15000)
    expect(api.listConnectionScans).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

})
