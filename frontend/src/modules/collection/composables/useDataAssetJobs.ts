/**
 * The data-asset job console: choose a profile (or explicit paths), dispatch it
 * to one probe, watch the progress the probe pushes, and read the final result.
 *
 * Progress is what the probe reports, not a client-side guess: `progress` and
 * `result.coverage` come from the server, which only accepts progress updates
 * that never change a task's status.
 *
 * The view keeps the template and the buttons; the polling timer, the API calls
 * and the page state live here.  The 5s timer is owned by this composable so an
 * unmounted page stops polling instead of leaving a hidden interval alive.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listProbes, type Probe } from '../../../api/probes'
import { listScanProfiles, queueDataAssetJob, type ScanProfile } from '../../../api/scanProfiles'
import { deleteTask, listTasks, stopTask } from '../../../api/tasks'
import { listAssetInstances, type AssetInstanceRow } from '../../../api/dataCatalog'
import type { Task } from '../../../types/task'

export function useDataAssetJobs() {
  const loading = ref(true)
  const error = ref('')
  const probes = ref<Probe[]>([])
  const profiles = ref<ScanProfile[]>([])
  const jobs = ref<Task[]>([])
  const probeId = ref<number | null>(null)
  const profileId = ref<number | null>(null)
  const pathsText = ref('')
  const dispatching = ref(false)
  const autoRefresh = ref(true)
  const assetJob = ref<Task | null>(null)
  const assetRows = ref<AssetInstanceRow[]>([])
  const assetLoading = ref(false)
  const assetError = ref('')
  const assetPage = ref(1)
  const assetTotal = ref(0)
  const assetAssociation = ref('')
  let assetRequest = 0
  let timer: number | undefined

  async function loadAssets(page = 1): Promise<void> {
    if (!assetJob.value) return
    const version = ++assetRequest
    const id = assetJob.value.id
    assetPage.value = page
    assetLoading.value = true
    assetError.value = ''
    assetRows.value = []
    try {
      const result = await listAssetInstances({ task_id: id, page, page_size: 50 })
      if (version !== assetRequest) return
      assetRows.value = result.items
      assetTotal.value = result.total
      assetAssociation.value = result.association || 'latest_scan_only'
    } catch (err) {
      if (version === assetRequest) assetError.value = err instanceof Error ? err.message : String(err)
    } finally {
      if (version === assetRequest) assetLoading.value = false
    }
  }

  async function openAssets(job: Task): Promise<void> {
    assetJob.value = job
    assetTotal.value = 0
    assetAssociation.value = ''
    await loadAssets()
  }

  function closeAssets(): void {
    assetRequest += 1
    assetJob.value = null
    assetLoading.value = false
  }

  const selectedProfile = computed(() => profiles.value.find((item) => item.id === profileId.value) || null)

  async function loadJobs(): Promise<void> {
    try {
      const result = await listTasks({ kind: 'data_asset_scan', page: 1, page_size: 50 })
      jobs.value = result.items
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    }
  }

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [probeResult, profileResult] = await Promise.all([
        listProbes({ page: 1, page_size: 200 }),
        listScanProfiles({ page: 1, page_size: 200 }),
      ])
      probes.value = probeResult.items
      profiles.value = profileResult.items
      if (probeId.value === null) probeId.value = probeResult.items[0]?.id ?? null
      if (profileId.value === null) profileId.value = profileResult.items[0]?.id ?? null
      await loadJobs()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  async function dispatch(): Promise<void> {
    const target = probeId.value
    if (!target) return
    dispatching.value = true
    try {
      // Explicit paths win over the profile, which is the documented behaviour of
      // the existing job API; sending only profile_id keeps the snapshot path.
      const payload: Record<string, unknown> = pathsText.value.trim()
        ? { paths: pathsText.value.split('\n').map((line) => line.trim()).filter(Boolean) }
        : { profile_id: profileId.value }
      if (pathsText.value.trim() && profileId.value) payload.profile_id = profileId.value
      const task = await queueDataAssetJob(target, payload)
      ElMessage.success(`已下发任务 #${task.id}`)
      await loadJobs()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      dispatching.value = false
    }
  }

  async function cancel(job: Task): Promise<void> {
    try {
      await stopTask(job.id)
      ElMessage.success(`任务 #${job.id} 已取消（探针在下一个检查点停止，不会 kill 掉 Agent）`)
      await loadJobs()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  async function remove(job: Task): Promise<void> {
    try {
      await deleteTask(job.id)
      ElMessage.success('已从列表移除（探针记录保留）')
      await loadJobs()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function coverageOf(job: Task): Record<string, unknown> {
    const result = (job.result || {}) as Record<string, unknown>
    return (result.coverage || {}) as Record<string, unknown>
  }

  function resultOf(job: Task): Record<string, unknown> {
    return (job.result || {}) as Record<string, unknown>
  }

  /**
   * One honest label for a scope that was not fully covered. A walk that reached
   * the end of the tree but read some files only up to the content limit is not
   * the same event as a directory that was never listed, and the two must not be
   * described with the same words.
   */
  function coverageNote(job: Task): string {
    const coverage = coverageOf(job)
    if (coverage.complete_scope !== false) return ''
    if (coverage.enumeration_complete === true && coverage.content_complete === false) {
      return '· 目录已完整枚举，部分文件内容按上限截断'
    }
    return '· 范围未完整覆盖'
  }

  function statusType(status: string): 'success' | 'warning' | 'danger' | 'info' | 'primary' {
    if (status === 'Success') return 'success'
    if (status === 'Pending' || status === 'Running') return 'primary'
    if (status === 'Partial') return 'warning'
    if (status === 'Cancelled') return 'info'
    if (status === 'Failed') return 'danger'
    return 'info'
  }

  const running = computed(() => jobs.value.filter((job) => job.status === 'Pending' || job.status === 'Running').length)
  const finished = computed(() => jobs.value.filter((job) => job.status === 'Success').length)
  const partial = computed(() => jobs.value.filter((job) => job.status === 'Partial').length)

  onMounted(async () => {
    await load()
    timer = window.setInterval(() => {
      if (autoRefresh.value) void loadJobs()
    }, 5000)
  })
  onBeforeUnmount(() => { if (timer) window.clearInterval(timer) })

  return {
    assetJob, assetRows, assetLoading, assetError, assetPage, assetTotal, assetAssociation,
    openAssets, closeAssets, loadAssets,
    loading,
    error,
    probes,
    profiles,
    jobs,
    probeId,
    profileId,
    pathsText,
    dispatching,
    autoRefresh,
    selectedProfile,
    loadJobs,
    load,
    dispatch,
    cancel,
    remove,
    coverageOf,
    resultOf,
    coverageNote,
    statusType,
    running,
    finished,
    partial,
  }
}
