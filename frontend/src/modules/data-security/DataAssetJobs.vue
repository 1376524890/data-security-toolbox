<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { listProbes, type Probe } from '../../api/probes'
import { listScanProfiles, queueDataAssetJob, type ScanProfile } from '../../api/scanProfiles'
import { deleteTask, stopTask } from '../../api/tasks'
import { apiGet } from '../../api/client'
import type { Task } from '../../types/task'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'

/**
 * The data-asset job console: choose a profile (or explicit paths), dispatch it
 * to one probe, watch the progress the probe pushes, and read the final result.
 *
 * Progress is what the probe reports, not a client-side guess: `progress` and
 * `result.coverage` come from the server, which only accepts progress updates
 * that never change a task's status.
 */
const router = useRouter()
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
let timer: number | undefined

const selectedProfile = computed(() => profiles.value.find((item) => item.id === profileId.value) || null)

async function loadJobs(): Promise<void> {
  try {
    const result = await apiGet<{ items: Task[] }>('/tasks', { kind: 'data_asset_scan', page: 1, page_size: 50 })
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
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar">
        <div class="toolbar-title">数据资产采集任务</div>
        <div class="toolbar-spacer" />
        <el-checkbox v-model="autoRefresh">自动刷新（5s）</el-checkbox>
        <el-button @click="loadJobs">刷新</el-button>
        <el-button @click="router.push('/scan-profiles')">扫描配置</el-button>
      </div>

      <div class="stat-grid cols-4">
        <StatCard label="进行中" :value="running" tone="primary" sub="Pending / Running" />
        <StatCard label="成功" :value="finished" tone="success" />
        <StatCard label="部分完成" :value="partial" tone="warning" sub="到达预算上限或未覆盖全部范围" />
        <StatCard label="可见任务" :value="jobs.length" sub="最近 50 条" />
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />下发新任务</div>
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 10px"
                  title="路径留空时使用所选扫描配置的 include_paths；显式填写路径则覆盖配置。探针在下次轮询时领取任务。" />
        <el-form label-width="110px">
          <el-form-item label="扫描配置">
            <el-select v-model="profileId" clearable placeholder="选择配置（可选）" style="width: 320px">
              <el-option v-for="item in profiles" :key="item.id"
                         :label="`${item.name} v${item.version}${item.enabled ? '' : '（已停用）'}`" :value="item.id" />
            </el-select>
            <span v-if="selectedProfile" class="muted" style="margin-left: 10px">
              {{ selectedProfile.include_paths.join('  ') || '未设置包含路径' }}
            </span>
          </el-form-item>
          <el-form-item label="覆盖路径">
            <el-input v-model="pathsText" type="textarea" :rows="2" placeholder="每行一个绝对路径；留空则使用配置" />
          </el-form-item>
          <el-form-item label="目标探针">
            <el-select v-model="probeId" placeholder="选择探针" style="width: 320px">
              <el-option v-for="probe in probes" :key="probe.id"
                         :label="`${probe.name}（${probe.ip_address || probe.hostname}）· ${probe.status}`" :value="probe.id" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="dispatching" :disabled="!probeId" @click="dispatch">下发任务</el-button>
          </el-form-item>
        </el-form>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot" />任务与进度</div>
        <el-table :data="jobs" size="small" empty-text="暂无数据资产任务">
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column label="状态" width="110">
            <template #default="{ row }">
              <el-tag size="small" :type="statusType(row.status)">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="进度" min-width="200">
            <template #default="{ row }">
              <el-progress :percentage="Math.min(row.progress || 0, 100)"
                           :status="row.status === 'Failed' ? 'exception' : row.status === 'Success' ? 'success' : undefined" />
              <div class="muted small">{{ row.current_stage }}</div>
            </template>
          </el-table-column>
          <el-table-column label="覆盖情况" min-width="220">
            <template #default="{ row }">
              <span v-if="(row.result || {}).files_analyzed === undefined && !Object.keys(coverageOf(row)).length" class="muted">—</span>
              <span v-else class="muted small">
                文件 {{ coverageOf(row).files_analyzed ?? '—' }} / {{ coverageOf(row).max_files ?? '—' }}，
                目录 {{ coverageOf(row).directories_visited ?? '—' }}，
                读取 {{ coverageOf(row).bytes_read ?? '—' }} 字节
                <span v-if="coverageOf(row).complete_scope === false" class="warn-text">· 范围未完整覆盖</span>
              </span>
            </template>
          </el-table-column>
          <el-table-column label="结果" width="200">
            <template #default="{ row }">
              <span v-if="row.result && row.result.assets !== undefined" class="small">
                资产 {{ row.result.assets }}，未观测到 {{ row.result.not_observed ?? 0 }}
                <span v-if="row.result.complete_scope === false" class="warn-text">（未完整覆盖，不会标记数据消失）</span>
              </span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column prop="error" label="错误" min-width="140" show-overflow-tooltip>
            <template #default="{ row }"><span class="danger-text">{{ row.error || '' }}</span></template>
          </el-table-column>
          <el-table-column label="操作" width="190" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" size="small"
                         @click="router.push({ path: '/data-types' })">数据类型</el-button>
              <el-button link size="small" :disabled="!['Pending', 'Running'].includes(row.status)"
                         @click="cancel(row)">取消</el-button>
              <el-button link type="danger" size="small"
                         :disabled="['Pending', 'Running'].includes(row.status)" @click="remove(row)">移除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot warn" />尚未接入（P1）</div>
        <el-alert type="warning" :closable="false" show-icon
                  title="定时巡检、增量计划与业务系统范围（P1）尚未实现：平台不会自动下发扫描，也不会声称已按业务系统归类。" />
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.toolbar-title { font-weight: 600; }
.muted { color: var(--soc-text-dim); }
.small { font-size: 12px; }
.warn-text { color: #f59e0b; }
.danger-text { color: #ef4444; }
</style>
