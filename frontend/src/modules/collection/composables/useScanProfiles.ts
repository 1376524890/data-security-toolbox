/**
 * The scan-profile console: the versioned scan configurations, the create/edit
 * draft and the dispatch dialog.
 *
 * A ScanProfile is a versioned scan configuration. `enabled` only means "usable
 * for a job" - it never turns scheduled collection on, and the probe's own
 * `[data].enabled` remains the switch that decides whether the host scans.
 *
 * The view keeps the template and the buttons; the API calls and the page state
 * live here.  `setPage` exists because moving the pager must also re-query.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  createScanProfile, deleteScanProfile, listScanProfiles, runScanProfile, updateScanProfile,
  type ScanProfile, type ScanProfileDraft,
} from '../../../api/scanProfiles'
import { listProbes, type Probe } from '../../../api/probes'

export function useScanProfiles() {
  const loading = ref(true)
  const error = ref('')
  const profiles = ref<ScanProfile[]>([])
  const probes = ref<Probe[]>([])
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(20)

  const dialog = ref(false)
  const saving = ref(false)
  const editingId = ref<number | null>(null)
  const runDialog = ref(false)
  const runProfile = ref<ScanProfile | null>(null)
  const runProbeId = ref<number | null>(null)

  function emptyDraft(): ScanProfileDraft {
    return {
      name: '', description: '', include_paths: [], exclude_paths: [], file_types: [],
      max_files: 200, max_dirs: 500, max_depth: 3, max_runtime_seconds: 120,
      max_bytes_read: 512 * 1024 * 1024, max_single_file_size: 2 * 1024 * 1024,
      max_full_hash_size: 8 * 1024 * 1024, large_file_sampling: true,
      sample_block_size: 64 * 1024, max_sample_rows: 25, max_cpu_seconds: 0, max_rss_mb: 0,
      xlsx_max_entries: 512, xlsx_max_uncompressed_bytes: 64 * 1024 * 1024,
      xlsx_max_compression_ratio: 200, xlsx_max_shared_strings: 200000,
      xlsx_max_sheets: 32, xlsx_max_columns: 256, xlsx_max_rows: 200,
      enabled: true, scheduled: false, interval_seconds: 3600,
    }
  }

  const draft = reactive<ScanProfileDraft>(emptyDraft())
  const includePathsText = ref('')
  const excludePathsText = ref('')

  const activeProfiles = computed(() => profiles.value.filter((item) => item.enabled).length)
  const scheduledProfiles = computed(() => profiles.value.filter((item) => item.scheduled).length)

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [profileResult, probeResult] = await Promise.all([
        listScanProfiles({ page: page.value, page_size: pageSize.value }),
        listProbes({ page: 1, page_size: 200 }),
      ])
      profiles.value = profileResult.items
      total.value = profileResult.total
      probes.value = probeResult.items
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  function openCreate(): void {
    editingId.value = null
    Object.assign(draft, emptyDraft())
    includePathsText.value = ''
    excludePathsText.value = ''
    dialog.value = true
  }

  function openEdit(row: ScanProfile): void {
    editingId.value = row.id
    Object.assign(draft, { ...emptyDraft(), ...row })
    includePathsText.value = row.include_paths.join('\n')
    excludePathsText.value = row.exclude_paths.join('\n')
    dialog.value = true
  }

  function splitLines(value: string): string[] {
    return value.split('\n').map((line) => line.trim()).filter(Boolean)
  }

  async function save(): Promise<void> {
    saving.value = true
    try {
      const payload: Partial<ScanProfileDraft> = {
        ...draft,
        include_paths: splitLines(includePathsText.value),
        exclude_paths: splitLines(excludePathsText.value),
      }
      if (editingId.value === null) {
        await createScanProfile(payload)
        ElMessage.success('已创建扫描配置')
      } else {
        await updateScanProfile(editingId.value, payload)
        ElMessage.success('已更新扫描配置（版本号 +1，已登记任务仍按旧快照执行）')
      }
      dialog.value = false
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    } finally {
      saving.value = false
    }
  }

  async function remove(row: ScanProfile): Promise<void> {
    try {
      await ElMessageBox.confirm(`删除扫描配置「${row.name}」？已下发的任务不受影响。`, '确认删除')
    } catch {
      return
    }
    try {
      await deleteScanProfile(row.id)
      ElMessage.success('已删除')
      await load()
    } catch (err) {
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function openRun(row: ScanProfile): void {
    runProfile.value = row
    runProbeId.value = probes.value[0]?.id ?? null
    runDialog.value = true
  }

  async function dispatch(): Promise<void> {
    if (!runProfile.value || !runProbeId.value) return
    try {
      const task = await runScanProfile(runProfile.value.id, runProbeId.value)
      runDialog.value = false
      ElMessage.success(`已下发任务 #${task.id}，可在数据资产任务页查看进度`)
    } catch (err) {
      // 409/400 here are real refusals (probe busy, empty include_paths), so the
      // server reason is surfaced instead of a generic failure.
      ElMessage.error(err instanceof Error ? err.message : String(err))
    }
  }

  function setPage(value: number): void {
    page.value = value
    void load()
  }

  onMounted(load)

  return {
    loading,
    error,
    profiles,
    probes,
    total,
    page,
    pageSize,
    dialog,
    saving,
    editingId,
    runDialog,
    runProfile,
    runProbeId,
    draft,
    includePathsText,
    excludePathsText,
    activeProfiles,
    scheduledProfiles,
    load,
    openCreate,
    openEdit,
    save,
    remove,
    openRun,
    dispatch,
    setPage,
  }
}
