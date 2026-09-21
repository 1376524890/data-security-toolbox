/**
 * The task-dispatch state: one wizard that turns "target + connection + scope +
 * detection items + schedule" into the right platform call. Probe targets go
 * through the probe data-asset job; platform-direct targets go through their own
 * source scan. A scheduled probe task is expressed as a ScanProfile that carries
 * the interval, so the schedule has a single home.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listProbes, type Probe } from '../../../api/probes'
import { listFileSources, runFileSource, type FileSource } from '../../../api/fileSources'
import { listDatabaseConnections, startDatabaseScan, type DatabaseConnection } from '../../../api/databaseConnections'
import { createScanProfile, queueDataAssetJob } from '../../../api/scanProfiles'
import { listPolicyGroups, type PolicyGroup } from '../../../api/policyGroups'

export type TargetKind = 'probe' | 'file_source' | 'database'

export function useTaskDispatch() {
  const targetKind = ref<TargetKind>('probe')
  const probes = ref<Probe[]>([])
  const sources = ref<FileSource[]>([])
  const connections = ref<DatabaseConnection[]>([])
  const groups = ref<PolicyGroup[]>([])
  const busy = ref(false)
  const lastTaskId = ref<number | null>(null)

  const draft = reactive({
    probeId: undefined as number | undefined,
    sourceId: undefined as number | undefined,
    connectionId: undefined as number | undefined,
    paths: '',
    excludePaths: '',
    fileTypes: '',
    policyGroupIds: [] as number[],
    mode: 'once' as 'once' | 'scheduled',
    intervalSeconds: 3600,
  })

  const targets = computed(() => {
    if (targetKind.value === 'probe') return probes.value.map((p) => ({ id: p.id, label: `${p.name} · ${p.ip_address || '未知IP'}`, status: p.status }))
    if (targetKind.value === 'file_source') return sources.value.map((s) => ({ id: s.id, label: `${s.name} · ${s.protocol}://${s.host}`, status: s.last_status }))
    return connections.value.map((c) => ({ id: c.id, label: `${c.name} · ${c.engine}://${c.host}:${c.port}`, status: c.enabled ? 'enabled' : 'disabled' }))
  })

  function lines(text: string): string[] {
    return text.split(/[\n,]/).map((value) => value.trim()).filter(Boolean)
  }

  async function load(): Promise<void> {
    const [probePage, sourcePage, connectionPage, groupPage] = await Promise.all([
      listProbes({ page: 1, page_size: 200 }),
      listFileSources(1),
      listDatabaseConnections({ page: 1, page_size: 200 }),
      listPolicyGroups({ page: 1, page_size: 200 }),
    ])
    probes.value = probePage.items
    sources.value = sourcePage.items
    connections.value = connectionPage.items
    groups.value = groupPage.items
  }

  async function submit(): Promise<void> {
    busy.value = true
    lastTaskId.value = null
    try {
      if (targetKind.value === 'probe') {
        if (!draft.probeId) throw new Error('请选择探针')
        const payload: Record<string, unknown> = {
          paths: lines(draft.paths), exclude_paths: lines(draft.excludePaths),
          file_types: lines(draft.fileTypes), policy_group_ids: draft.policyGroupIds,
        }
        if (draft.mode === 'scheduled') {
          const profile = await createScanProfile({
            name: `定时采集 ${new Date().toISOString().slice(0, 16)}`,
            include_paths: lines(draft.paths), exclude_paths: lines(draft.excludePaths),
            file_types: lines(draft.fileTypes), scheduled: true,
            interval_seconds: draft.intervalSeconds,
          })
          payload.profile_id = profile.id
        }
        const task = await queueDataAssetJob(draft.probeId, payload)
        lastTaskId.value = task.id
      } else if (targetKind.value === 'file_source') {
        if (!draft.sourceId) throw new Error('请选择共享文件来源')
        const task = await runFileSource(draft.sourceId, 'scan')
        lastTaskId.value = task.id
      } else {
        if (!draft.connectionId) throw new Error('请选择数据库连接')
        const task = await startDatabaseScan(draft.connectionId, { schemas: [], tables: [] })
        lastTaskId.value = task.id
      }
      ElMessage.success(`任务已下发${lastTaskId.value ? `（#${lastTaskId.value}）` : ''}`)
    } catch (err) {
      ElMessage.error(String(err))
    } finally {
      busy.value = false
    }
  }

  onMounted(load)
  return { targetKind, draft, targets, groups, busy, lastTaskId, load, submit }
}
