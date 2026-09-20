/**
 * The incident centre: the paged incident list, the detail of the selected
 * incident, its status transitions and the manual correlation tool.
 *
 * The severity/status filter fields and the attack-stage labels stay in the view,
 * because they are static presentation; everything the server answers with lives
 * here.
 */
import { onMounted, reactive, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { listIncidents, getIncident, updateIncidentStatus, correlateIncidents } from '../../../../api/incidents'
import type { Incident, IncidentFilters } from '../../../../types/incident'
import { incidentStages } from '../../../../types/incident'

export function useIncidentCenter() {
  const loading = ref(true)
  const error = ref('')
  const items = ref<Incident[]>([])
  const total = ref(0)
  const selected = ref<Incident | null>(null)
  const detail = ref<Incident | null>(null)
  const detailLoading = ref(false)
  const filters = reactive<IncidentFilters>({ search: '', status: '', severity: '', page: 1, page_size: 50 })

  const activeStages = computed(() => { const inc = detail.value || selected.value; return inc ? incidentStages(inc) : [] })
  const findings = computed(() => detail.value?.findings?.items || [])

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await listIncidents({ ...filters })
      items.value = result.items
      total.value = result.total
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function open(row: Incident): Promise<void> {
    selected.value = row
    detailLoading.value = true
    try {
      detail.value = await getIncident(row.id)
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      detailLoading.value = false
    }
  }

  async function changeStatus(status: string): Promise<void> {
    if (!selected.value) return
    try {
      await updateIncidentStatus(selected.value.id, status)
      ElMessage.success(`状态已更新为 ${status}`)
      await open(selected.value)
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function reset(): void { filters.page = 1; load() }

  // --- Manual incident correlation ---
  const correlateOpen = ref(false)
  const correlateRunning = ref(false)
  const correlateFindings = ref('')
  const correlateWindow = ref(3600)
  const correlateResult = ref<Array<Record<string, unknown>>>([])

  async function runCorrelate(): Promise<void> {
    if (!correlateFindings.value.trim()) {
      ElMessage.warning('请输入待关联的发现 JSON')
      return
    }
    correlateRunning.value = true
    correlateResult.value = []
    try {
      const findings = JSON.parse(correlateFindings.value)
      if (!Array.isArray(findings)) throw new Error('发现必须是一个数组')
      correlateResult.value = await correlateIncidents(findings as Array<Record<string, unknown>>, correlateWindow.value)
      ElMessage.success(`关联完成，共生成 ${correlateResult.value.length} 个事件`)
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      correlateRunning.value = false
    }
  }

  onMounted(load)
  return {
    loading,
    error,
    items,
    total,
    selected,
    detail,
    detailLoading,
    filters,
    activeStages,
    findings,
    correlateOpen,
    correlateRunning,
    correlateFindings,
    correlateWindow,
    correlateResult,
    load,
    open,
    changeStatus,
    reset,
    runCorrelate,
  }
}
