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
 * ``GET /tasks`` cannot filter on a payload/result field, so the list is paged
 * by the server and filtered here; ``taskTotal`` keeps the server's own count so
 * the page can say "N 条检查任务，其中 M 条含密码评估" instead of implying the
 * inventory is smaller than it is.
 */
import { computed, ref, type Ref } from 'vue'
import { listTasks } from '../../../api/tasks'
import type { Task } from '../../../types/task'
import type { CryptoProfileLike } from '../../tasks/assessment/composables/useCryptoAssessment'

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
  load: () => Promise<void>
  setPage: (next: number) => Promise<void>
}

export function useCryptoAssessmentResults(pageSize = 20): UseCryptoAssessmentResults {
  const rows = ref<CryptoAssessmentRow[]>([])
  const taskTotal = ref(0)
  const page = ref(1)
  const loading = ref(false)
  const error = ref('')
  const selectedId = ref<number | null>(null)

  const selected = computed(
    () => rows.value.find((row) => row.id === selectedId.value) || null)
  const selectedProfiles = computed(() => selected.value?.profiles || {})

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const result = await listTasks({ kind: 'scan', page: page.value, page_size: pageSize })
      const items = (result.items || []) as unknown as Task[]
      taskTotal.value = Number(result.total || 0)
      rows.value = items
        .map(toRow)
        .filter((row): row is CryptoAssessmentRow => row !== null)
      // Keep the selection meaningful after a refresh: a task that fell off the
      // page must not stay selected, or the panel would show a stale profile.
      if (selectedId.value !== null && !rows.value.some((row) => row.id === selectedId.value)) {
        selectedId.value = null
      }
      if (selectedId.value === null && rows.value.length) {
        selectedId.value = rows.value[0].id
      }
    } catch (err) {
      error.value = String(err)
      rows.value = []
    } finally {
      loading.value = false
    }
  }

  /** Paging is one action, so the query and the page number cannot drift. */
  async function setPage(next: number): Promise<void> {
    page.value = Math.max(1, next)
    await load()
  }

  return {
    rows, taskTotal, page, pageSize, loading, error, selectedId, selected, selectedProfiles,
    load, setPage,
  }
}
