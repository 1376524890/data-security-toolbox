/**
 * 风险文件 state: the list, the risk points of the opened file, and the two
 * source reads behind it (masked browse, whole-file download).
 *
 * Opening a row loads its risk points straight away: "why is this file risky"
 * is the first question an operator asks, and hiding it behind another click
 * was the thing this page got wrong. Browsing starts masked and only shows the
 * file as it is on the host when the operator explicitly asks for 查看全部.
 */
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  downloadRiskFile, getRiskContent, getRiskPoints, listRiskFiles,
  type RiskContent, type RiskFile, type RiskPoints,
} from '../../../api/riskFiles'
import { useAutoRefresh } from '../../../composables/useAutoRefresh'
import { useTableSort } from '../../../composables/useTableSort'

export function useRiskFiles() {
  const loading = ref(true)
  const error = ref('')
  const rows = ref<RiskFile[]>([])
  const total = ref(0)
  const filters = reactive({
    page: 1, page_size: 50, search: '', source_kind: '', severity: '', coverage: '',
    order_by: undefined as string | undefined,
  })

  // Sorting is a server-side action here: the list is paginated, so reordering
  // only the rows already on screen would reorder a page, not the inventory.
  const { onSortChange, orderBy } = useTableSort(() => { filters.page = 1; void load() })

  const selected = ref<RiskFile | null>(null)
  const drawer = ref(false)

  const riskPoints = ref<RiskPoints | null>(null)
  const riskLoading = ref(false)
  const riskError = ref('')

  const browse = ref<RiskContent | null>(null)
  const browseLoading = ref(false)
  const browseError = ref('')
  const revealAll = ref(false)

  async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
    if (!silent) { loading.value = true; error.value = '' }
    try {
      filters.order_by = orderBy()
      const page = await listRiskFiles(filters)
      rows.value = page.items
      total.value = page.total
      error.value = ''
    } catch (err) {
      // A background refresh must not blank a list an operator is reading.
      if (!silent) error.value = String(err)
    } finally {
      if (!silent) loading.value = false
    }
  }

  // A risk file only changes when a scan finishes, so a minute is frequent
  // enough to feel current without re-reading the inventory every few seconds.
  useAutoRefresh(load, { intervalMs: 60000 })

  function setPage(page: number): void {
    filters.page = page
    void load()
  }

  /** Opening a file loads its risk points, not just its metadata. */
  async function open(row: RiskFile): Promise<void> {
    selected.value = row
    drawer.value = true
    resetReads()
    riskLoading.value = true
    try {
      riskPoints.value = await getRiskPoints(row.id)
      riskError.value = ''
    } catch (err) {
      riskPoints.value = null
      riskError.value = String(err)
    } finally {
      riskLoading.value = false
    }
  }

  function resetReads(): void {
    riskPoints.value = null
    riskError.value = ''
    browse.value = null
    browseError.value = ''
    revealAll.value = false
  }

  /**
   * Read the file back from its source. ``mask`` is the server's default and
   * what the browse button asks for; 查看全部 is the same read without masking.
   */
  async function browseContent(mask = true): Promise<void> {
    const row = selected.value
    if (!row) return
    browseLoading.value = true
    browseError.value = ''
    try {
      browse.value = await getRiskContent(row.id, mask)
      revealAll.value = !mask
    } catch (err) {
      browseError.value = String(err)
    } finally {
      browseLoading.value = false
    }
  }

  async function download(): Promise<void> {
    const row = selected.value
    if (!row) return
    try {
      await downloadRiskFile(row.id, row.name)
      ElMessage.success(`已开始下载 ${row.name}`)
    } catch (err) {
      ElMessage.error(String(err))
    }
  }

  onMounted(load)

  return {
    loading, error, rows, total, filters, selected, drawer,
    riskPoints, riskLoading, riskError,
    browse, browseLoading, browseError, revealAll,
    load, setPage, open, browseContent, download, resetReads, onSortChange,
  }
}
