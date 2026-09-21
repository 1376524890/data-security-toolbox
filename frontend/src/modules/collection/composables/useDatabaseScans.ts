import { onBeforeUnmount, ref, type Ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  getDatabaseConnection, getScanDetail, listConnectionScans,
  type ConnectionDetail, type ScanDetail, type ScanSummary,
} from '../../../api/databaseConnections'

export function useDatabaseScans(selectedId: Ref<number | null>, error: Ref<string>) {
  const detail = ref<ConnectionDetail | null>(null)
  const scanDetail = ref<ScanDetail | null>(null)
  const scanOpen = ref(false)
  const autoRefresh = ref(true)
  let timer: number | undefined

  async function loadScans(): Promise<void> {
    const id = selectedId.value
    if (!id) return
    try {
      const result = await listConnectionScans(id, 20)
      if (detail.value && detail.value.id === id) detail.value = { ...detail.value, scans: result.items }
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    }
  }

  async function loadDetail(): Promise<void> {
    const id = selectedId.value
    if (!id) {
      detail.value = null
      return
    }
    try {
      detail.value = await getDatabaseConnection(id)
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    }
  }

  async function openScan(row: ScanSummary): Promise<void> {
    scanOpen.value = true
    scanDetail.value = null
    try {
      scanDetail.value = await getScanDetail(row.task_id)
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  // The coordinator starts polling after the initial list/detail request finishes.
  function startPolling(): void {
    timer = window.setInterval(() => {
      if (!autoRefresh.value) return
      void loadScans()
    }, 5000)
  }
  onBeforeUnmount(() => { if (timer) window.clearInterval(timer) })

  return { detail, scanDetail, scanOpen, autoRefresh, loadScans, loadDetail, openScan, startPolling }
}
