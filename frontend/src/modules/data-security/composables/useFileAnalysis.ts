/**
 * The file-analysis workbench: the file list with its filters, the detail drawer
 * and the 4s refresh that keeps an open drawer current.
 *
 * The polling timer is owned by this composable, so an unmounted page stops
 * refreshing instead of leaving a hidden interval alive.  A background refresh
 * failure stays quiet here: the manual refresh still reports it normally.
 *
 * The view keeps the filter field config, the row-to-badge wording (`scanOutcome`)
 * and the download helper, because those are presentation rather than state.
 */
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost, apiUpload } from '../../../api/client'
import type { PageResult } from '../../../types/common'

// Exported so the page can type the rows it renders; the two interfaces moved
// with the state they describe.
export interface FileRecord { id: number; name: string; path: string; size: number; sha256: string; file_type: string; metadata_json: Record<string, unknown>; risk_level: string; created_at: string }
export interface FileDetail { file: FileRecord; findings: Array<Record<string, unknown>>; data_assets: Array<Record<string, unknown>> }

export function useFileAnalysis() {
  const loading = ref(true)
  const error = ref('')
  const rows = ref<FileRecord[]>([])
  const total = ref(0)
  const detail = ref<FileDetail | null>(null)
  const drawer = ref(false)
  const uploading = ref(false)
  const hiddenInfo = computed(() => detail.value?.file.metadata_json.hidden_info as { hidden: boolean; findings: Array<{ kind: string; description: string; bytes?: number; preview?: string }> } | undefined)
  let refreshTimer: ReturnType<typeof setInterval> | undefined
  const filters = reactive({ search: '', file_type: '', risk_level: '', page: 1, page_size: 50 })

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await apiGet<PageResult<FileRecord>>('/files', { ...filters })
      rows.value = result.items
      total.value = result.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function handleUpload(file: File): Promise<void> {
    if (!file) return
    uploading.value = true
    try {
      await apiUpload('/files/upload', file)
      ElMessage.success('文件已上传')
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      uploading.value = false
    }
  }

  async function open(row: FileRecord): Promise<void> {
    try {
      detail.value = await apiGet<FileDetail>(`/files/${row.id}`)
      drawer.value = true
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  async function reanalyze(row: FileRecord): Promise<void> {
    try {
      await apiPost(`/files/${row.id}/analyze`)
      ElMessage.success('已触发重新分析')
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function reset(): void { filters.page = 1; load() }

  onMounted(() => {
    load()
    refreshTimer = setInterval(async () => {
      if (!drawer.value || !detail.value) return
      const id = detail.value.file.id
      try {
        const updated = await apiGet<FileDetail>(`/files/${id}`)
        if (drawer.value && detail.value?.file.id === id) detail.value = updated
      } catch { /* Manual refresh retains the normal error message. */ }
    }, 4000)
  })
  onBeforeUnmount(() => { if (refreshTimer) clearInterval(refreshTimer) })
  return {
    loading,
    error,
    rows,
    total,
    detail,
    drawer,
    uploading,
    hiddenInfo,
    filters,
    load,
    handleUpload,
    open,
    reanalyze,
    reset,
  }
}
