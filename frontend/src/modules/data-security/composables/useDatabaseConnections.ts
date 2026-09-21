/** Coordinates connection selection and refresh; each child owns one workflow. */
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  deleteDatabaseConnection, listDatabaseConnections, testDatabaseConnection,
  type DatabaseConnection, type EngineOption,
} from '../../../api/databaseConnections'
import { useDatabaseConnectionForm } from './useDatabaseConnectionForm'
import { useDatabaseScope } from './useDatabaseScope'
import { useDatabaseScans } from './useDatabaseScans'
import { reasonLabel, statusType, testLabel } from '../databaseConnectionPresentation'

export type { ConnectionForm } from './useDatabaseConnectionForm'

export function useDatabaseConnections() {
  const loading = ref(true)
  const error = ref('')
  const connections = ref<DatabaseConnection[]>([])
  const engines = ref<EngineOption[]>([])
  const note = ref('')

  const testing = ref<number | null>(null)
  const selectedId = ref<number | null>(null)
  const selectedConnection = computed(
    () => connections.value.find((item) => item.id === selectedId.value),
  )
  const scans = useDatabaseScans(selectedId, error)
  const { detail, loadScans, loadDetail } = scans
  const scope = useDatabaseScope(selectedConnection, loadScans)
  const { pickedTables, schemas, tables } = scope
  const editor = useDatabaseConnectionForm(engines, (id) => { selectedId.value = id }, load)
  const enabledCount = computed(() => connections.value.filter((row) => row.enabled).length)
  const reachableCount = computed(
    () => connections.value.filter((row) => row.last_test_status === 'ok').length,
  )
  const runsOn = computed(() => {
    const row = selectedConnection.value
    return row ? `${row.host}:${row.port} · ${row.database || '(未指定库)'}` : ''
  })

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await listDatabaseConnections({ page: 1, page_size: 200 })
      connections.value = result.items
      engines.value = result.engines
      note.value = result.note
      // A deleted target falls back to the first remaining one, and the detail
      // always follows the selection so the page cannot show a stale connection.
      if (selectedId.value === null
          || !result.items.some((row) => row.id === selectedId.value)) {
        selectedId.value = result.items[0]?.id ?? null
      }
      if (selectedId.value === null) detail.value = null
      else await loadDetail()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function select(row: DatabaseConnection): Promise<void> {
    selectedId.value = row.id
    pickedTables.value = []
    await loadDetail()
  }

  async function remove(row: DatabaseConnection): Promise<void> {
    try {
      const result = await deleteDatabaseConnection(row.id)
      ElMessage.success(`连接已删除；已采集到的 ${result.kept_instances} 个资产保留为历史`)
      if (selectedId.value === row.id) {
        selectedId.value = null
        detail.value = null
        schemas.value = []
        tables.value = []
      }
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  async function test(row: DatabaseConnection): Promise<void> {
    testing.value = row.id
    try {
      const result = await testDatabaseConnection(row.id)
      const outcome = String((result.result || {}).status || '')
      if (outcome === 'ok') {
        const version = String((result.result || {}).server_version || '')
        ElMessage.success(`连接成功（${version}；只读会话）`)
      } else {
        ElMessage.error(`连接失败：${String((result.result || {}).error || outcome)}`)
      }
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      testing.value = null
    }
  }

  onMounted(async () => {
    await load()
    scans.startPolling()
  })

  return {
    loading, error, connections, engines, note, testing,
    selectedId, runsOn, enabledCount, reachableCount,
    load, select, remove, test,
    ...editor, ...scope,
    detail, loadScans, loadDetail,
    scanOpen: scans.scanOpen, scanDetail: scans.scanDetail,
    autoRefresh: scans.autoRefresh, openScan: scans.openScan,
    statusType, testLabel, reasonLabel,
  }
}
