/**
 * The alert centre: the paged alert list with its summary cards, the detail of
 * the selected alert and its status transitions.
 *
 * The filter field config stays in the view, because it is static presentation;
 * everything the server answers with lives here.
 */
import { onMounted, reactive, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { listAlerts, getAlert, updateAlert, getAlertSummary, type AlertQuery } from '../../../../api/alerts'
import type { Alert, AlertDetail, AlertSummary } from '../../../../types/alert'

export function useAlertCenter() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<Alert[]>([])
  const total = ref(0)
  const selected = ref<Alert | null>(null)
  const detail = ref<AlertDetail | null>(null)
  const detailLoading = ref(false)
  const summary = ref<AlertSummary | null>(null)
  const filters = reactive<AlertQuery>({ search: '', status: '', severity: '', page: 1, page_size: 50 })

  const confidence = computed(() => detail.value?.finding?.confidence)

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [result, sum] = await Promise.all([listAlerts({ ...filters }), getAlertSummary()])
      items.value = result.items
      total.value = result.total
      summary.value = sum
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function open(row: Alert): Promise<void> {
    selected.value = row
    detailLoading.value = true
    try {
      detail.value = await getAlert(row.id)
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      detailLoading.value = false
    }
  }

  async function changeStatus(status: string): Promise<void> {
    if (!selected.value) return
    try {
      await updateAlert(selected.value.id, { status })
      ElMessage.success(`已标记为 ${status}`)
      await open(selected.value)
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function reset(): void { filters.page = 1; load() }

  onMounted(load)
  return {
    loading,
    error,
    items,
    total,
    selected,
    detail,
    detailLoading,
    summary,
    filters,
    confidence,
    load,
    open,
    changeStatus,
    reset,
  }
}
