/**
 * 密码评估 results, read back from the 检查任务 that produced them.
 *
 * The assessment itself runs in the browser (``assessCrypto``); the server only
 * holds the observed facts. A 检查任务 is a ``kind='scan'`` task with
 * ``payload.crypto_assess``, and the facts land in ``result.crypto_profiles``
 * (host -> profile). Until now that result was only reachable by opening the
 * task's detail drawer in 任务中心, so a past assessment could not be read from
 * the asset side at all — this composable lists the tasks that carry one.
 *
 * A task is how the facts were *collected*, not how an operator looks for a
 * result: ``assets`` therefore folds every loaded task into one row per host,
 * with the newest observation of that host winning, so each asset shows its
 * standing verdict without anyone having to remember which task observed it.
 *
 * ``GET /tasks`` cannot filter on a payload/result field, so the list is paged
 * by the server and filtered here; ``taskTotal`` keeps the server's own count so
 * the page can say "N 条检查任务，其中 M 条含密码评估" instead of implying the
 * inventory is smaller than it is.
 */
import { computed, reactive, ref, type Ref } from 'vue'
import { listTasks } from '../../../api/tasks'
import { useAutoRefresh } from '../../../composables/useAutoRefresh'
import { useTableSort, sortRows } from '../../../composables/useTableSort'
import type { Task } from '../../../types/task'
import { assessCrypto } from '../../tasks/assessment/cryptoAssessment'
import { configFromProfile, type CryptoProfileLike }
  from '../../tasks/assessment/composables/useCryptoAssessment'

export interface CryptoAssessmentRow {
  id: number
  target: string
  status: string
  finishedAt: string
  hostCount: number
  profiles: Record<string, CryptoProfileLike>
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {}
}

/** The profiles a task actually produced, or an empty map.
 *
 *  A task that was cancelled, failed, or ran without ``crypto_assess`` has no
 *  profiles rather than an empty-looking one, so it is left out of the list
 *  entirely — an assessment nobody ran is not a result. */
export function profilesOf(task: Task): Record<string, CryptoProfileLike> {
  const result = asRecord(task.result)
  const profiles = asRecord(result.crypto_profiles)
  return profiles as Record<string, CryptoProfileLike>
}

export function toRow(task: Task): CryptoAssessmentRow | null {
  const profiles = profilesOf(task)
  const hosts = Object.keys(profiles)
  if (!hosts.length) return null
  const payload = asRecord(task.payload)
  return {
    id: task.id,
    target: String(payload.target || ''),
    status: task.status,
    finishedAt: task.finished_at || task.created_at || '',
    hostCount: hosts.length,
    profiles,
  }
}

/**
 * One host's standing 密码评估 result, folded across every loaded 检查任务.
 *
 * ``level``/``overallScore`` are the same GB/T 39786 verdict the panel prints
 * for a single host, computed through the same ``configFromProfile`` +
 * ``assessCrypto`` pair, so the row and the panel can never disagree.
 */
export interface CryptoAssetRow {
  host: string
  target: string
  observedAt: string
  taskId: number
  taskStatus: string
  level: string
  overallScore: number
  violations: number
  profile: CryptoProfileLike
}

/** Levels from worst to best, so "highest risk first" is a real order. */
const LEVEL_RANK: Record<string, number> = {
  '不合规': 0, '部分合规': 1, '基本合规': 2, '合规': 3,
}

export function assetSortValue(row: CryptoAssetRow, prop: string): unknown {
  if (prop === 'level') return LEVEL_RANK[row.level] ?? -1
  return (row as unknown as Record<string, unknown>)[prop]
}

/**
 * Fold task rows into one row per host. A host observed by several tasks keeps
 * the newest observation — an assessment is a statement about the asset as it
 * was last seen, not about one run — while every task stays readable below.
 */
export function toAssetRows(rows: CryptoAssessmentRow[]): CryptoAssetRow[] {
  const newest = new Map<string, CryptoAssessmentRow>()
  const ordered = [...rows].sort((left, right) =>
    (left.finishedAt || '').localeCompare(right.finishedAt || '') || left.id - right.id)
  for (const row of ordered) {
    for (const host of Object.keys(row.profiles)) newest.set(host, row)
  }
  const assets: CryptoAssetRow[] = []
  for (const [host, row] of newest) {
    const profile = row.profiles[host]
    const result = assessCrypto(configFromProfile(profile))
    assets.push({
      host, target: row.target, observedAt: row.finishedAt, taskId: row.id,
      taskStatus: row.status, level: result.level,
      overallScore: result.overallScore, violations: result.summary.violations, profile,
    })
  }
  // Newest observation first, the order an operator reads a standing result in.
  return assets.sort((left, right) =>
    (right.observedAt || '').localeCompare(left.observedAt || '') || left.host.localeCompare(right.host))
}

export interface UseCryptoAssessmentResults {
  rows: Ref<CryptoAssessmentRow[]>
  taskTotal: Ref<number>
  page: Ref<number>
  pageSize: number
  loading: Ref<boolean>
  error: Ref<string>
  selectedId: Ref<number | null>
  selected: Ref<CryptoAssessmentRow | null>
  selectedProfiles: Ref<Record<string, CryptoProfileLike>>
  assets: Ref<CryptoAssetRow[]>
  visibleAssets: Ref<CryptoAssetRow[]>
  assetTotal: Ref<number>
  assetFilters: { search: string }
  assetTable: ReturnType<typeof useTableSort>
  selectedHost: Ref<string>
  selectAsset: (host: string) => void
  panelProfiles: Ref<Record<string, CryptoProfileLike>>
  panelTitle: Ref<string>
  load: (options?: { silent?: boolean }) => Promise<void>
  setPage: (next: number) => Promise<void>
  onSortChange: (change: { prop: string | null; order: 'ascending' | 'descending' | null }) => void
}

export function useCryptoAssessmentResults(pageSize = 20): UseCryptoAssessmentResults {
  const rows = ref<CryptoAssessmentRow[]>([])
  const taskTotal = ref(0)
  const page = ref(1)
  const loading = ref(false)
  const error = ref('')
  const selectedId = ref<number | null>(null)

  // The asset view is the standing one, so its filter and sort are client-side
  // (the rows are folded from the tasks already on the page) and it owns its own
  // sort state — one shared with the task table would make a click in one table
  // re-order the other.
  const assetFilters = reactive({ search: '' })
  const assetTable = useTableSort()
  const selectedHost = ref('')

  // Server-side sort over the task list this page reads back: only the keys the
  // /tasks endpoint whitelists are offered in the table.
  const { onSortChange, orderBy } = useTableSort(() => { page.value = 1; void load() })
  const selected = computed(
    () => rows.value.find((row) => row.id === selectedId.value) || null)
  const selectedProfiles = computed(() => selected.value?.profiles || {})

  const assets = computed(() => toAssetRows(rows.value))
  const assetTotal = computed(() => assets.value.length)
  const visibleAssets = computed(() => {
    const needle = assetFilters.search.trim().toLowerCase()
    const matched = assets.value.filter((row) => !needle
      || [row.host, row.target, row.level].some((field) => String(field || '').toLowerCase().includes(needle)))
    return sortRows(matched, assetTable.sort.prop, assetTable.sort.order, assetSortValue)
  })

  /** The one panel on the page follows the last thing the operator picked: an
   *  asset (the standing result) or a task (that run's hosts). */
  const pickedAsset = computed(() => assets.value.find((row) => row.host === selectedHost.value) || null)
  const panelProfiles = computed(() => (pickedAsset.value
    ? { [pickedAsset.value.host]: pickedAsset.value.profile } : selectedProfiles.value))
  const panelTitle = computed(() => (pickedAsset.value
    ? `${pickedAsset.value.host} 资产常驻评估结果（观测于任务 #${pickedAsset.value.taskId}，GB/T 39786 / GM/T）`
    : selected.value
      ? `${selected.value.target || '#' + selected.value.id} 网络扫描观测结果（商用密码应用安全性评估，GB/T 39786 / GM/T）`
      : ''))

  /** Picking one side clears the other, so the panel is never ambiguous. */
  function selectAsset(host: string): void {
    selectedHost.value = host
    selectedId.value = null
  }

  async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
    if (!silent) { loading.value = true; error.value = '' }
    try {
      const result = await listTasks({
        kind: 'scan', page: page.value, page_size: pageSize, order_by: orderBy(),
      })
      const items = (result.items || []) as unknown as Task[]
      taskTotal.value = Number(result.total || 0)
      rows.value = items
        .map(toRow)
        .filter((row): row is CryptoAssessmentRow => row !== null)
      // Keep the selection meaningful after a refresh: a task or host that fell
      // off the page must not stay selected, or the panel would show a stale
      // profile. A host also disappears when its task does, so the asset side is
      // checked first — the standing asset view is what the page opens on.
      if (selectedHost.value && !assets.value.some((row) => row.host === selectedHost.value)) {
        selectedHost.value = ''
      }
      if (selectedId.value !== null && !rows.value.some((row) => row.id === selectedId.value)) {
        selectedId.value = null
      }
      if (!selectedHost.value && selectedId.value === null) {
        selectedHost.value = visibleAssets.value[0]?.host || ''
      }
    } catch (err) {
      // A failed background refresh keeps the last good result set; only an
      // explicit load may blank the page.
      if (!silent) { error.value = String(err); rows.value = [] }
    } finally {
      if (!silent) loading.value = false
    }
  }

  // 密码评估 results only appear when a 检查任务 finishes, so a minute is ample.
  useAutoRefresh(load, { intervalMs: 60000 })

  /** Paging is one action, so the query and the page number cannot drift. */
  async function setPage(next: number): Promise<void> {
    page.value = Math.max(1, next)
    await load()
  }

  return {
    rows, taskTotal, page, pageSize, loading, error, selectedId, selected, selectedProfiles,
    assets, visibleAssets, assetTotal, assetFilters, assetTable, selectedHost, selectAsset,
    panelProfiles, panelTitle,
    load, setPage, onSortChange,
  }
}
