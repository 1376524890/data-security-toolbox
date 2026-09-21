import { computed, ref, type ComputedRef } from 'vue'
import { ElMessage } from 'element-plus'
import {
  listConnectionSchemas, listConnectionTables, startDatabaseScan,
  type DatabaseConnection, type TableRow,
} from '../../../api/databaseConnections'

// Selection is shared by reference so every operation uses the coordinator's target.
export function useDatabaseScope(
  selectedConnection: ComputedRef<DatabaseConnection | undefined>,
  loadScans: () => Promise<void>,
) {
  const scopeLoading = ref(false)
  const schemas = ref<string[]>([])
  const schema = ref('')
  const tables = ref<TableRow[]>([])
  const pickedTables = ref<string[]>([])
  const dispatching = ref(false)
  const confirmedTables = computed(() => tables.value.filter((item) => item.kind === 'table').length)

  async function loadScope(): Promise<void> {
    const row = selectedConnection.value
    if (!row) return
    scopeLoading.value = true
    try {
      const result = await listConnectionSchemas(row.id)
      schemas.value = result.schemas
      schema.value = result.default
      await loadTables()
    } catch (err) {
      schemas.value = []
      tables.value = []
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      scopeLoading.value = false
    }
  }

  async function loadTables(): Promise<void> {
    const row = selectedConnection.value
    if (!row || !schema.value) {
      tables.value = []
      return
    }
    try {
      const result = await listConnectionTables(row.id, schema.value)
      tables.value = result.tables
    } catch (err) {
      tables.value = []
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function toggleTable(name: string): void {
    pickedTables.value = pickedTables.value.includes(name)
      ? pickedTables.value.filter((item) => item !== name)
      : [...pickedTables.value, name]
  }

  function qualified(name: string): string {
    return schema.value ? `${schema.value}.${name}` : name
  }

  async function start(): Promise<void> {
    const row = selectedConnection.value
    if (!row) return
    dispatching.value = true
    try {
      const task = await startDatabaseScan(row.id, {
        schemas: schema.value ? [schema.value] : [],
        tables: pickedTables.value.map((name) => qualified(name)),
      })
      ElMessage.success(`已下发数据库采集任务 #${task.id}（配置快照 ${task.config_hash}）`)
      await loadScans()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      dispatching.value = false
    }
  }

  return {
    scopeLoading, schemas, schema, tables, pickedTables, dispatching, confirmedTables,
    loadScope, loadTables, toggleTable, start,
  }
}
