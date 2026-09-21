/**
 * The page template itself: the state tests cover the composable, but a broken
 * binding only shows up when the view actually renders. This mounts the real
 * component with Element Plus and checks what an operator would see.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, nextTick, type App } from 'vue'
import ElementPlus from 'element-plus'
import DatabaseConnections from '../modules/data-security/DatabaseConnections.vue'
import type { ConnectionDetail, ConnectionList, DatabaseConnection, ScanSummary } from '../api/databaseConnections'
import * as api from '../api/databaseConnections'

vi.mock('../api/databaseConnections', () => ({
  listDatabaseConnections: vi.fn(), createDatabaseConnection: vi.fn(),
  getDatabaseConnection: vi.fn(), updateDatabaseConnection: vi.fn(),
  deleteDatabaseConnection: vi.fn(), testDatabaseConnection: vi.fn(),
  listConnectionSchemas: vi.fn(), listConnectionTables: vi.fn(),
  startDatabaseScan: vi.fn(), listConnectionScans: vi.fn(), getScanDetail: vi.fn(),
}))

const connection = (overrides: Partial<DatabaseConnection> = {}): DatabaseConnection => ({
  id: 3, name: 'kali-mariadb', engine: 'mysql', engine_label: 'MySQL / MariaDB',
  host: '192.168.191.130', port: 3306, database: 'dst_demo', username: 'dst_ro',
  password_set: true, tls_mode: '', options: {}, enabled: true,
  last_test_at: '2026-09-20T12:00:00', last_test_status: 'ok', last_test_error: '',
  last_scan_at: '2026-09-20T12:05:00', created_at: '', updated_at: '',
  ...overrides,
})

const scan = (overrides: Partial<ScanSummary> = {}): ScanSummary => ({
  task_id: 41, status: 'Success', stage: '完成', progress: 100, error: '',
  created_at: '', started_at: '', finished_at: '', duration_seconds: 2.5,
  connection_id: 3, scope: { schemas: ['dst_demo'], tables: [] }, config_hash: 'abcd1234',
  server_version: '11.8.6-MariaDB-6 from Debian', engine: 'mysql',
  host: '192.168.191.130', port: 3306, database: 'dst_demo', schemas: ['dst_demo'],
  tables_total: 9, tables_selected: 9, tables_scanned: 9, tables_failed: 0,
  rows_read: 213, values_scanned: 900, hits: 11, objects: 9, detections: 9,
  complete_scope: true, termination_reason: 'complete', read_only: true,
  categories: ['phone'], not_observed: 0, engine_version: '1.0.0',
  ruleset_version: '2026.09', sample_rows: 50, notes: [], ...overrides,
})

let app: App
let host: HTMLElement

const flush = async () => {
  for (let index = 0; index < 5; index += 1) await Promise.resolve()
  await nextTick()
  await new Promise((resolve) => setTimeout(resolve, 0))
  await nextTick()
}

const button = (label: string) => Array.from(document.body.querySelectorAll('button'))
  .find((item) => item.textContent?.trim() === label)

beforeEach(async () => {
  vi.clearAllMocks()
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.mocked(api.listDatabaseConnections).mockResolvedValue({
    items: [connection()], total: 1, page: 1, page_size: 200,
    engines: [{ engine: 'mysql', label: 'MySQL / MariaDB', default_port: 3306 }],
    note: '由服务端 worker 直接连接目标数据库；密码只写不读。',
  } as ConnectionList)
  vi.mocked(api.getDatabaseConnection).mockResolvedValue(
    { ...connection(), scans: [scan()] } as ConnectionDetail)
  vi.mocked(api.listConnectionScans).mockResolvedValue(
    { connection_id: 3, items: [scan()], count: 1 })
  vi.mocked(api.listConnectionSchemas).mockResolvedValue(
    { connection_id: 3, schemas: ['dst_demo'], count: 1, default: 'dst_demo' })
  vi.mocked(api.listConnectionTables).mockResolvedValue({
    schema: 'dst_demo', count: 2, tables: [
      { name: 'customers', kind: 'table', schema: 'dst_demo', columns: 7 },
      { name: 'order_view', kind: 'view', schema: 'dst_demo', columns: 2 },
    ],
  })
  vi.mocked(api.getScanDetail).mockResolvedValue({
    id: 41, kind: 'database_scan', status: 'Success', progress: 100,
    current_stage: '完成', error: '', result: {},
    summary: { ...scan(), tables: [
      { path: 'dst_demo.customers', rows_read: 50, values_scanned: 350, hits: 3,
        detections: 3, categories: ['phone', 'id_card', 'email'], candidates: [] },
      { path: 'dst_demo.clean_notes', rows_read: 50, values_scanned: 150, hits: 0,
        detections: 0, categories: [], candidates: [] },
    ], table_errors: [] },
  })
  host = document.createElement('div')
  document.body.append(host)
  app = createApp(DatabaseConnections)
  app.use(ElementPlus)
  app.mount(host)
  await flush()
})

afterEach(() => {
  app.unmount()
  host.remove()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

describe('database connections page', () => {
  it('renders the configured target, its state and the scan history', () => {
    const text = host.textContent || ''
    expect(text).toContain('目标数据库连接')
    expect(text).toContain('kali-mariadb')
    expect(text).toContain('192.168.191.130:3306')
    expect(text).toContain('dst_ro')
    expect(text).toContain('已保存')
    expect(text).toContain('连通')
    expect(text).toContain('由服务端 worker 直接连接目标数据库')
    // The queued task, not a client guess.
    expect(text).toContain('9 / 9')
    expect(text).toContain('完整读取')
  })

  it('reads the real schema and table list from the target when asked', async () => {
    button('读取库与表')!.click()
    await flush()
    expect(api.listConnectionSchemas).toHaveBeenCalledWith(3)
    expect(api.listConnectionTables).toHaveBeenCalledWith(3, 'dst_demo')
    const text = host.textContent || ''
    expect(text).toContain('customers')
    expect(text).toContain('order_view')
    // Nothing is picked yet, and a view is not selectable even though it is listed.
    expect(text).toContain('0 张（该库共 1 张普通表）')
    const boxes = Array.from(host.querySelectorAll<HTMLElement>('.el-checkbox'))
    expect(boxes).toHaveLength(2)
    boxes[0].click()
    await flush()
    expect(host.textContent).toContain('1 张（该库共 1 张普通表）')
  })

  it('explains the write-only password rule in the create form', async () => {
    button('新建连接')!.click()
    await flush()
    expect(document.body.textContent).toContain('新建数据库连接')
    expect(document.body.textContent).toContain('接口只回传 password_set')
  })

  it('shows the per-table breakdown of one scan, including the negative control', async () => {
    button('详情')!.click()
    await flush()
    expect(api.getScanDetail).toHaveBeenCalledWith(41)
    const text = document.body.textContent || ''
    expect(text).toContain('dst_demo.customers')
    expect(text).toContain('dst_demo.clean_notes')
    expect(text).toContain('phone、id_card、email')
    expect(text).toContain('已确认只读')
  })

  it('submits the child form through the shared draft and closes it after saving', async () => {
    vi.mocked(api.createDatabaseConnection).mockResolvedValueOnce(connection({ id: 9 }))
    button('新建连接')!.click()
    await flush()
    const input = (placeholder: string, value: string) => {
      const field = document.body.querySelector<HTMLInputElement>(`input[placeholder="${placeholder}"]`)!
      field.value = value
      field.dispatchEvent(new Event('input', { bubbles: true }))
    }
    input('例如 业务库-只读盘点', 'new-target')
    input('IP 或主机名，例如 192.168.191.130', '10.0.0.5')
    input('留空表示无密码', 'new-password')
    await flush()
    button('保存')!.click()
    await flush()
    expect(api.createDatabaseConnection).toHaveBeenCalledWith(expect.objectContaining({
      name: 'new-target', host: '10.0.0.5', password: 'new-password',
    }))
    button('新建连接')!.click()
    await flush()
    expect(document.body.querySelector<HTMLInputElement>('input[placeholder="留空表示无密码"]')!.value).toBe('')
  })

  it('clears the scope selection before dispatching the whole schema', async () => {
    vi.mocked(api.startDatabaseScan).mockResolvedValueOnce({
      id: 77, status: 'Pending', location: 'platform', connection_id: 3, config_hash: 'hash',
    })
    button('读取库与表')!.click()
    await flush()
    host.querySelector<HTMLElement>('.el-checkbox')!.click()
    await flush()
    button('清空选择')!.click()
    await flush()
    expect(host.textContent).toContain('0 张（该库共 1 张普通表）')
    button('启动采集')!.click()
    await flush()
    expect(api.startDatabaseScan).toHaveBeenCalledWith(3, { schemas: ['dst_demo'], tables: [] })
  })

})
