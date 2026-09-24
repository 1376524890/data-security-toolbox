<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useAutoRefresh } from '../../composables/useAutoRefresh'
import { useTableSort } from '../../composables/useTableSort'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { ElMessageBox } from 'element-plus'
import { deleteTask, getTask, listTasks, stopTask } from '../../api/tasks'
import { canStop } from '../../api/taskKinds'
import { deleteProbe } from '../../api/probes'
import type { Task } from '../../types/task'
import { formatCoverageLimit, formatDateTime, formatTerminationReason } from '../../utils/format'
import CryptoAssessmentPanel from './assessment/CryptoAssessmentPanel.vue'
import type { CryptoProfileLike } from './assessment/composables/useCryptoAssessment'
import { TASK_TYPES, useTaskWizard } from './composables/useTaskWizard'

// 任务中心: the task list (progress + health, expandable to a detail and a short
// problem summary) and the only place a scan is dispatched — the "新建任务"
// wizard on the right.
const loading = ref(true)
const error = ref('')
const rows = ref<Task[]>([])
const total = ref(0)
const filters = reactive({
  page: 1, page_size: 50, status: '', kind: '', search: '',
  order_by: undefined as string | undefined,
})

// Sorting travels to the server: the list is paginated, so ordering the rows on
// screen would reorder a page rather than the queue.
const { onSortChange, orderBy } = useTableSort(() => { filters.page = 1; void load() })
const detail = ref<Task | null>(null)

const wizardOpen = ref(false)
const wizard = useTaskWizard()

type TreeInstance = {
  setCheckedKeys: (keys: string[]) => void
  getCheckedKeys: (leafOnly?: boolean) => string[]
}

// Each host owns an el-tree; keeping the instance lets "清空选择" reset the
// checkboxes themselves instead of only the stored keys (the two drifted apart).
const trees = new Map<number, TreeInstance>()
function registerTree(key: number, instance: unknown): void {
  const tree = instance as Partial<TreeInstance> | null | undefined
  if (typeof tree?.setCheckedKeys === 'function' && typeof tree.getCheckedKeys === 'function') {
    trees.set(key, tree as TreeInstance)
  }
}

// el-tree hands its handler the checked keys, but only to a function — binding
// `onTreeCheck(host)` to @check is exactly that, and the keys can be read back
// from the instance we already registered. (Binding a handler *factory* here
// instead would silently do nothing: Vue compiles any non-function handler
// expression into `$event => { … }` and drops what the factory returns.)
function onTreeCheck(host: { key: number } & Record<string, unknown>): void {
  wizard.onCheck(host as never, trees.get(host.key)?.getCheckedKeys() ?? [])
}
function clearHostSelection(host: { key: number } & Record<string, unknown>): void {
  trees.get(host.key)?.setCheckedKeys([])
  wizard.onCheck(host as never, [])
}

// 'monitoring' is the long-lived task a probe's capture segments hang under;
// 'pcap' reaches the individual segments when they are needed.
const KINDS = ['monitoring', 'pcap', 'probe_scan', 'data_asset_scan', 'scan',
  'file_source_scan', 'database_scan']

// A monitoring target that is not registered yet: the wizard keeps the dialog
// open for these so the hand-install steps stay on screen until it calls back.
const failedHosts = computed(() => wizard.hosts.value.filter(
  (host) => !host.registered && (host.deployError || host.manual)))

async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
  if (!silent) { loading.value = true; error.value = '' }
  try {
    filters.order_by = orderBy()
    const page = await listTasks({ ...filters })
    rows.value = page.items
    total.value = page.total
    error.value = ''
  } catch (err) {
    // Keep the last good queue on screen: a failed poll must not look like an
    // empty task list.
    if (!silent) error.value = String(err)
  } finally {
    if (!silent) loading.value = false
  }
}

// Tasks move while an operator watches, so this is the fastest page timer in
// the console; the in-flight guard keeps a slow server from stacking requests.
useAutoRefresh(load, { intervalMs: 15000 })

/** A short, honest read of a task's health from the fields the worker reports. */
function health(task: Task): { label: string; tone: string } {
  if (task.status === 'Failed') return { label: task.error || '失败', tone: 'danger' }
  if (task.status === 'Partial') return { label: task.error || '部分完成', tone: 'warning' }
  if (task.status === 'Running') return { label: task.current_stage || '运行中', tone: 'primary' }
  if (task.status === 'Pending') return { label: task.current_stage || '排队中', tone: 'info' }
  if (task.status === 'Cancelled') return { label: '已取消', tone: 'info' }
  return { label: task.current_stage || '完成', tone: 'success' }
}

/** Coverage facts a scan reports, in the order an operator reads them. The task
 *  result also carries raw arrays; those are listed separately below so a
 *  "partial" scan can be explained without opening the database. */
const COVERAGE_LABELS: [string, string][] = [
  ['complete_scope', '覆盖完整'],
  ['enumeration_complete', '目录遍历完整'],
  ['content_complete', '文件内容完整'],
  ['termination_reason', '终止原因'],
  ['termination_detail', '终止细节'],
  ['assets', '已采集文件'],
  ['skipped', '已跳过'],
  ['sampled_count', '仅采样内容'],
  ['metadata_only', '仅登记元数据'],
  ['unreadable_count', '未能读取'],
  ['bytes_read', '读取字节'],
  ['source_name', '文件源'],
  ['operation', '操作'],
]

function coverageFacts(task: Task): { label: string; value: string }[] {
  const result = (task.result || {}) as Record<string, unknown>
  return COVERAGE_LABELS.filter(([key]) => result[key] !== undefined && result[key] !== null)
    .map(([key, label]) => ({ label, value: coverageValue(key, result[key]) }))
}

function coverageValue(key: string, value: unknown): string {
  return key.startsWith('termination_') ? formatTerminationReason(String(value)) : String(value)
}

/** Keys already answered above, so the raw 结果 block does not repeat them and
 *  an operator does not have to guess which of the two rows is authoritative. */
const PRESENTED_KEYS = new Set([
  ...COVERAGE_LABELS.map(([key]) => key),
  'unreadable', 'sampled', 'unreadable_count', 'sampled_count',
  // Rendered by the 密码评估 section instead of as one opaque row.
  'crypto_profiles', 'crypto_profile_hosts',
])

function remainingResult(task: Task): [string, unknown][] {
  return Object.entries((task.result || {}) as Record<string, unknown>)
    .filter(([key]) => !PRESENTED_KEYS.has(key))
}

/** Paths a scan could not read or only sampled, listed in full: the count alone
 *  cannot tell an operator which part of a share they are missing. */
function problemPaths(task: Task): { label: string; paths: string[] }[] {
  const result = (task.result || {}) as Record<string, unknown>
  const groups: { label: string; paths: string[] }[] = []
  for (const [key, label] of [['unreadable', '未能读取'], ['sampled', '仅采样内容']] as const) {
    const rows = result[key]
    if (!Array.isArray(rows) || !rows.length) continue
    groups.push({
      label,
      paths: rows.map((row) => {
        const item = row as { path?: unknown; reason?: unknown }
        return `${String(item.path ?? '')}${item.reason ? ` — ${String(item.reason)}` : ''}`
      }),
    })
  }
  return groups
}

/** What a scan was dispatched with: the root it read and the limits it ran
 *  under, with 0 spelled out as 不限制. Without this the console showed the
 *  result but never the configuration that produced it. */
function scanConfig(task: Task): { label: string; value: string }[] {
  const config = ((task.payload || {}) as Record<string, unknown>).config as
    Record<string, unknown> | undefined
  if (!config) return []
  const limits = (config.limits || {}) as Record<string, number>
  const rows: { label: string; value: string }[] = []
  if (config.root_path) rows.push({ label: '根目录', value: String(config.root_path) })
  if (config.host) rows.push({ label: '目标', value: `${String(config.host)}:${String(config.port ?? '')}` })
  for (const [key, label] of [
    ['max_files', '文件上限'], ['max_depth', '目录深度'], ['max_bytes', '读取字节上限'],
    ['max_file_bytes', '单文件上限'], ['max_seconds', '执行时限（秒）'],
  ] as const) {
    if (limits[key] === undefined) continue
    rows.push({ label, value: formatCoverageLimit(limits[key]) })
  }
  return rows
}

/** The per-host crypto profiles a scan recorded, keyed by host address.
 *
 * The scan writes them as it fingerprints each host's services, so the 密码评估
 * panel can assess a host from facts it already collected. ``null`` means the
 * task carries none (a non-scan kind, or a scan run with the assessment off),
 * and the section stays hidden rather than opening an empty form. */
function cryptoProfiles(task: Task): Record<string, CryptoProfileLike> | null {
  const profiles = ((task.result || {}) as Record<string, unknown>).crypto_profiles
  if (!profiles || typeof profiles !== 'object') return null
  return Object.keys(profiles as Record<string, unknown>).length
    ? (profiles as Record<string, CryptoProfileLike>)
    : null
}

function duration(task: Task): string {
  if (!task.started_at) return '—'
  const start = new Date(task.started_at).getTime()
  const end = task.finished_at ? new Date(task.finished_at).getTime() : Date.now()
  const sec = Math.max(0, Math.round((end - start) / 1000))
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`
}

async function open(task: Task): Promise<void> {
  detail.value = await getTask(task.id)
}

/** The probe a 监测任务 installed is task-dedicated: stopping the task also
 *  takes it off its host, which is worth spelling out before an operator
 *  clicks, because it ends the capture as well. */
const MONITOR_STOP_HINT = '停止监测任务将同时取消该探针所有待分析的抓包片段，'
  + '并回收本任务部署的探针（卸载探针文件、删除记录）；主机上其它探针不受影响。'

async function stop(task: Task): Promise<void> {
  const monitor = task.kind === 'monitoring'
  try {
    await ElMessageBox.confirm(
      monitor ? MONITOR_STOP_HINT : `停止任务 #${task.id}？等待中的任务将不再下发；已领取的任务由探针检查后退出。`,
      monitor ? '停止监测任务' : '停止任务',
      { confirmButtonText: '停止', cancelButtonText: '取消', type: 'warning' },
    )
  } catch { return }
  try {
    await stopTask(task.id)
    ElMessage.success(monitor ? '已停止监测，探针回收已入队' : '已请求停止')
    await load()
  } catch (err) { ElMessage.error(String(err)) }
}

/** Retire the probe behind a monitoring task: uninstall it from its host with
 *  the credential the install retained, then drop the record. The server keeps
 *  the record when the removal fails, so the address that still needs cleaning
 *  is never lost. */
function monitorProbeId(task: Task): number | null {
  const probeId = Number(task.payload?.probe_id)
  return Number.isFinite(probeId) && probeId > 0 ? probeId : null
}

async function retireProbe(task: Task): Promise<void> {
  const probeId = monitorProbeId(task)
  if (!probeId) { ElMessage.error('该监测任务没有关联探针'); return }
  try {
    await ElMessageBox.confirm(
      `回收探针 #${probeId}？平台将连接该主机卸载探针并删除其记录，已采集的数据保留。`,
      '回收探针',
      { confirmButtonText: '回收', cancelButtonText: '取消', type: 'warning' },
    )
  } catch { return }
  try {
    const result = await deleteProbe(probeId, { remove_remote: true })
    ElMessage.success(result.deployment_id ? `已下发回收任务（#${result.deployment_id}）` : '已回收探针')
    await load()
  } catch (err) { ElMessage.error(String(err)) }
}

async function remove(task: Task): Promise<void> {
  try { await deleteTask(task.id); await load() }
  catch (err) { ElMessage.error(String(err)) }
}

async function openWizard(): Promise<void> {
  wizard.reset()
  if (!wizard.groups.value.length) await wizard.loadGroups()
  wizardOpen.value = true
}

async function submitWizard(): Promise<void> {
  const result = await wizard.submit()
  // Keep the dialog open while any target still needs the operator (a probe
  // that has not called back), so the hand-install steps are not thrown away.
  if (result.ok && !result.failed) {
    wizardOpen.value = false
  }
  if (result.ok) await load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <strong>任务中心</strong>
      <span class="muted">下发与进度监控；任务结束后按引用计数卸载探针</span>
      <div class="toolbar-spacer" />
      <el-input v-model="filters.search" clearable placeholder="类型 / 阶段 / 错误" style="width: 200px"
                @keyup.enter="load()" @clear="load()" />
      <el-select v-model="filters.status" clearable placeholder="全部状态" style="width: 140px" @change="load()">
        <el-option v-for="s in ['Pending', 'Running', 'Success', 'Failed', 'Partial', 'Cancelled']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="filters.kind" clearable placeholder="全部类型" style="width: 160px" @change="load()">
        <el-option v-for="k in KINDS" :key="k" :label="k" :value="k" />
      </el-select>
      <el-button @click="load()">刷新</el-button>
      <el-button type="primary" @click="openWizard">新建任务</el-button>
    </div>

    <StateBox :loading="loading" :error="error" :empty="!rows.length" empty-text="还没有任务" @retry="load">
      <el-table :data="rows" size="small" @row-click="open" @sort-change="onSortChange">
        <el-table-column prop="id" label="ID" width="80" sortable="custom" />
        <el-table-column prop="kind" label="类型" width="150" sortable="custom" />
        <el-table-column prop="status" label="状态" width="120" sortable="custom">
          <template #default="{ row }"><StatusBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column prop="progress" label="完成度" width="200" sortable="custom">
          <template #default="{ row }"><el-progress :percentage="Math.max(0, Math.min(100, row.progress || 0))" :stroke-width="10" /></template>
        </el-table-column>
        <el-table-column label="健康度" min-width="200">
          <template #default="{ row }"><el-tag size="small" :type="health(row).tone as never">{{ health(row).label }}</el-tag></template>
        </el-table-column>
        <el-table-column label="耗时" width="110"><template #default="{ row }">{{ duration(row) }}</template></el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180" sortable="custom"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button v-if="['Pending', 'Running'].includes(row.status) && canStop(row)" link type="warning" size="small" @click.stop="stop(row)">停止</el-button>
            <el-button v-if="row.kind === 'monitoring' && monitorProbeId(row)" link type="primary" size="small" @click.stop="retireProbe(row)">回收探针</el-button>
            <el-button link type="danger" size="small" @click.stop="remove(row)">移除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination background layout="total, prev, pager, next" :total="total" :page-size="filters.page_size"
                     :current-page="filters.page" style="margin-top: 10px"
                     @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <!-- Task detail: rendered in a window rather than an expandable row, so the
         progress, the health summary and the problem report read as one view. -->
    <el-dialog :model-value="detail !== null" :title="detail ? `任务 #${detail.id}` : ''"
               width="820px" top="8vh" @update:model-value="(v: boolean) => { if (!v) detail = null }">
      <template v-if="detail">
        <div class="stat-grid cols-3">
          <StatCard label="状态" :value="detail.status" :sub="detail.current_stage || '—'"
                    :tone="detail.status === 'Failed' ? 'danger' : detail.status === 'Success' ? 'success' : 'warning'" />
          <StatCard label="完成度" :value="`${detail.progress}%`" :sub="`类型 ${detail.kind}`" />
          <StatCard label="健康度" :value="health(detail).label" :sub="`耗时 ${duration(detail)}`"
                    :tone="health(detail).tone as never" />
        </div>
        <el-progress :percentage="Math.max(0, Math.min(100, detail.progress || 0))" style="margin-top: 12px" />
        <div v-if="detail.error" class="section-title">问题</div>
        <el-alert v-if="detail.error" type="error" :closable="false" :title="detail.error" />
        <div v-if="scanConfig(detail).length" class="section-title">扫描配置</div>
        <el-descriptions v-if="scanConfig(detail).length" :column="2" border size="small">
          <el-descriptions-item v-for="row in scanConfig(detail)" :key="row.label" :label="row.label">
            <span class="wrap">{{ row.value }}</span>
          </el-descriptions-item>
        </el-descriptions>
        <div v-if="coverageFacts(detail).length" class="section-title">覆盖情况</div>
        <el-descriptions v-if="coverageFacts(detail).length" :column="2" border size="small">
          <el-descriptions-item v-for="fact in coverageFacts(detail)" :key="fact.label" :label="fact.label">
            <span class="wrap">{{ fact.value }}</span>
          </el-descriptions-item>
        </el-descriptions>
        <template v-if="cryptoProfiles(detail)">
          <div class="section-title">密码评估</div>
          <CryptoAssessmentPanel :profiles="cryptoProfiles(detail) || {}"
                                 :title="`任务 #${detail.id} 网络扫描观测结果（商用密码应用安全性评估，GB/T 39786 / GM/T）`" />
        </template>
        <template v-if="problemPaths(detail).length">
          <div class="section-title">未能读取 / 仅采样</div>
          <div v-for="group in problemPaths(detail)" :key="group.label" class="path-group">
            <div class="muted">{{ group.label }}（{{ group.paths.length }}）</div>
            <pre class="log">{{ group.paths.join('\n') }}</pre>
          </div>
        </template>
        <div class="section-title">结果</div>
        <el-descriptions v-if="remainingResult(detail).length" :column="2" border size="small">
          <el-descriptions-item v-for="[key, value] in remainingResult(detail)" :key="key" :label="String(key)">
            <span class="wrap">{{ Array.isArray(value) ? `${value.length} 项` : String(value ?? '—') }}</span>
          </el-descriptions-item>
        </el-descriptions>
        <el-empty v-else-if="!Object.keys(detail.result || {}).length" description="该任务暂无结果"
                  :image-size="60" />
        <div v-else class="muted">其余字段已在上方「覆盖情况」中列出</div>
        <div v-if="detail.log" class="section-title">日志</div>
        <pre v-if="detail.log" class="log">{{ detail.log }}</pre>
      </template>
      <template #footer><el-button @click="detail = null">关闭</el-button></template>
    </el-dialog>

    <el-dialog v-model="wizardOpen" title="新建任务" width="980px" top="6vh">
      <el-steps :active="wizard.step.value" simple finish-status="success" style="margin-bottom: 14px">
        <el-step title="任务类型" />
        <el-step title="目标主机" />
        <el-step title="连接方式" />
        <el-step title="连通性测试" />
        <el-step title="检测范围" />
        <el-step title="任务属性" />
      </el-steps>

      <!-- 1. 任务类型：这次检查是一次性的还是要长期监测，决定后面是否下发探针 -->
      <template v-if="wizard.step.value === 0">
        <el-radio-group v-model="wizard.taskType.value" class="type-picker">
          <el-radio v-for="item in TASK_TYPES" :key="item.value" :value="item.value" border>
            <div class="type-label">{{ item.label }}</div>
            <div class="muted type-hint">{{ item.hint }}</div>
          </el-radio>
        </el-radio-group>
        <el-alert type="info" :closable="false" show-icon style="margin-top: 12px"
                  :title="wizard.taskType.value === 'monitoring'
                    ? '监测任务必须在目标主机部署探针；自动部署失败时会给出手动安装与回连步骤。'
                    : '检查任务不接触目标主机：平台直连读取勾选目录，并扫描其网络服务（指纹识别 + 漏洞库匹配），只执行一次。'" />
      </template>

      <!-- 2. 目标主机（IP/端口） -->
      <template v-else-if="wizard.step.value === 1">
        <el-table :data="wizard.hosts.value" size="small">
          <el-table-column label="IP / 主机" min-width="200"><template #default="{ row }"><el-input v-model="row.host" placeholder="10.0.0.10" @change="wizard.invalidate(row)" /></template></el-table-column>
          <el-table-column label="端口" width="110"><template #default="{ row }"><el-input-number v-model="row.port" :min="1" :max="65535" controls-position="right" style="width: 100%" @change="wizard.invalidate(row)" /></template></el-table-column>
          <el-table-column label="操作" width="90"><template #default="{ row }"><el-button link type="danger" @click="wizard.removeHost(row.key)">删除</el-button></template></el-table-column>
        </el-table>
        <el-button style="margin-top: 8px" @click="wizard.addHost">添加主机</el-button>
      </template>

      <!-- 3. 连接方式与凭据 -->
      <template v-else-if="wizard.step.value === 2">
        <div v-for="host in wizard.hosts.value" :key="host.key" class="host-block">
          <div class="host-title">{{ host.host }}:{{ host.port }}</div>
          <el-form label-width="110px" size="small">
            <el-form-item label="用户名">
              <el-select v-model="host.username" filterable allow-create default-first-option
                         placeholder="选择或输入用户名" style="width: 260px" @change="wizard.invalidate(host)">
                <el-option v-for="user in ['root', 'admin', 'administrator', 'dstprobe']" :key="user"
                           :label="user" :value="user" />
              </el-select>
            </el-form-item>
            <el-form-item v-if="wizard.taskType.value === 'inspection'" label="远程协议">
              <el-select v-model="host.protocol" style="width: 240px"
                         @change="(value: string) => { if (value !== 'sftp') host.port = 21; wizard.invalidate(host) }">
                <el-option label="SFTP（SSH，端口 22）" value="sftp" />
                <el-option label="FTPS（显式 TLS，端口 21）" value="ftps" />
                <el-option label="FTP（明文，端口 21）" value="ftp" />
              </el-select>
            </el-form-item>
            <el-form-item label="认证方式">
              <el-radio-group v-model="host.authType" @change="wizard.invalidate(host)">
                <el-radio-button value="password">密码</el-radio-button>
                <el-radio-button value="private_key">私钥</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item v-if="host.authType === 'password'" label="密码">
              <el-input v-model="host.password" type="password" show-password style="width: 320px" @change="wizard.invalidate(host)" />
            </el-form-item>
            <template v-else>
              <el-form-item label="私钥"><el-input v-model="host.privateKey" type="textarea" :rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" @change="wizard.invalidate(host)" /></el-form-item>
              <el-form-item label="私钥口令"><el-input v-model="host.keyPassphrase" type="password" show-password style="width: 260px" @change="wizard.invalidate(host)" /></el-form-item>
            </template>
          </el-form>
        </div>
      </template>

      <!-- 4. 连通性测试 -->
      <template v-else-if="wizard.step.value === 3">
        <el-table :data="wizard.hosts.value" size="small">
          <el-table-column label="目标" min-width="200"><template #default="{ row }">{{ row.host }}:{{ row.port }}</template></el-table-column>
          <el-table-column label="结果" min-width="260">
            <template #default="{ row }">
              <el-tag v-if="row.test" size="small" :type="row.test.ok ? 'success' : 'danger'">
                {{ row.test.ok ? `可达${row.hostKey ? ' · ' + row.hostKey.slice(0, 24) + '…' : ''}` : (row.test.message || row.test.error || '不可达') }}
              </el-tag>
              <span v-else class="muted">未测试</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="120"><template #default="{ row }"><el-button size="small" :loading="row.busy" @click="wizard.testHost(row)">测试</el-button></template></el-table-column>
        </el-table>
        <el-button style="margin-top: 8px" @click="wizard.hosts.value.forEach((h) => wizard.testHost(h))">全部测试</el-button>
      </template>

      <!-- 5. 检测范围（可展开目录树 + 级联勾选） -->
      <template v-else-if="wizard.step.value === 4">
        <div v-for="host in wizard.hosts.value" :key="host.key" class="host-block">
          <div class="host-title">{{ host.host }}：展开目录树并勾选检测范围</div>
          <div class="toolbar">
            <el-select v-model="host.root" filterable allow-create default-first-option
                       placeholder="选择或输入根目录" style="width: 260px">
              <el-option v-for="root in ['/', '/home', '/srv', '/data', '/var', '/opt', '/etc']"
                         :key="root" :label="root" :value="root" />
            </el-select>
            <span class="muted">已选 {{ host.selected.length }} 个目录</span>
            <div class="toolbar-spacer" />
            <el-button size="small" @click="clearHostSelection(host)">清空选择</el-button>
          </div>
          <!-- Lazy tree: ticking a directory takes its whole subtree; children
               load on expand, and files are shown but not tickable.
               @check has to stay an inline arrow: Vue compiles any non-function
               handler expression into `$event => { … }`, so binding a handler
               factory such as checkFor(host) calls it and drops the function it
               returns — the tick would show up in the tree but never reach the
               wizard, leaving 下发任务 greyed out. -->
          <el-tree :key="`${host.key}-${host.root}`" :ref="(el: unknown) => registerTree(host.key, el)"
                   lazy show-checkbox node-key="path"
                   :props="{ label: 'name', isLeaf: 'leaf', disabled: 'disabled' }"
                   :load="(node: any, resolve: any) => wizard.loadNode(host, node, resolve)"
                   @check="onTreeCheck(host)"
                   style="max-height: 260px; overflow: auto" />
        </div>
      </template>

      <!-- 6. 任务属性 -->
      <template v-else>
        <el-form label-width="130px" size="small">
          <el-form-item label="检测项（策略组）">
            <el-select v-model="wizard.policyGroupIds.value" multiple filterable placeholder="留空用默认规则" style="width: 420px">
              <el-option v-for="group in wizard.groups.value" :key="group.id" :label="group.name" :value="group.id" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="wizard.taskType.value === 'inspection'" label="端口范围">
            <el-select v-model="wizard.topPorts.value" style="width: 220px">
              <el-option v-for="item in [{ l: 'Top 100 端口', v: 100 }, { l: 'Top 200 端口', v: 200 }, { l: 'Top 1000 端口', v: 1000 }]"
                         :key="item.v" :label="item.l" :value="item.v" />
            </el-select>
            <span class="muted" style="margin-left: 10px">对目标网络服务做指纹识别与漏洞库匹配（nuclei 模板）</span>
          </el-form-item>
          <el-form-item v-if="wizard.taskType.value === 'inspection'" label="密码评估">
            <el-switch v-model="wizard.cryptoAssess.value" />
            <span class="muted" style="margin-left: 10px">
              用扫描已采集的服务 banner 与 TLS 握手，对每台主机做商用密码应用安全性评估（GB/T 39786 / GM/T），结果在任务详情里查看
            </span>
          </el-form-item>
          <el-form-item v-else label="数据采集间隔">
            <el-select v-model="wizard.intervalSeconds.value" style="width: 220px">
              <el-option :label="'不下发（仅抓流量）'" :value="0" />
              <el-option v-for="item in [{ l: '每小时', v: 3600 }, { l: '每 6 小时', v: 21600 }, { l: '每天', v: 86400 }]"
                         :key="item.v" :label="item.l" :value="item.v" />
            </el-select>
          </el-form-item>
        </el-form>

        <template v-if="wizard.taskType.value === 'monitoring' && failedHosts.length">
          <div class="section-title">探针自动部署失败，可改为手动安装</div>
          <div v-for="host in failedHosts" :key="host.key" class="host-block">
            <div class="host-title">{{ host.host }}：{{ host.deployError || '自动部署未成功' }}</div>
            <template v-if="host.manual">
              <div class="muted">在目标主机上按下面步骤安装，探针会在启动后自动回连（凭据 {{ host.manual.expires_at }} 前有效）：</div>
              <ol class="steps">
                <li v-for="(line, index) in host.manual.steps" :key="index">{{ line }}</li>
              </ol>
              <el-input :model-value="host.manual.toml" type="textarea" :rows="6" readonly />
              <div class="muted" style="margin: 6px 0">探针包：<span v-for="pkg in host.manual.packages" :key="`${pkg.version}-${pkg.arch}`" style="margin-right: 12px">
                {{ pkg.version }} / {{ pkg.arch }}（sha256 {{ pkg.sha256.slice(0, 12) }}…）
              </span></div>
            </template>
            <div class="toolbar" style="margin-top: 8px">
              <el-button size="small" :loading="host.checking" @click="wizard.checkCallback(host)">检测回连</el-button>
              <el-tag v-if="host.registered" size="small" type="success">已回连</el-tag>
              <el-tag v-else size="small" type="info">{{ host.deployStatus || '等待回连' }}</el-tag>
            </div>
          </div>
        </template>

        <el-alert type="info" :closable="false" show-icon style="margin-top: 12px"
                  :title="wizard.taskType.value === 'monitoring'
                    ? '下发的探针是任务专属的：凭据加密保留至任务结束，任务到达终态后自动卸载并销毁凭据；同一主机若还有其它在用任务则不卸载。手工注册的探针永远不会被自动卸载。'
                    : '检查任务只执行一次：平台读取勾选目录并扫描目标端口，不在目标主机上安装或改动任何东西。'" />
      </template>

      <template #footer>
        <span v-if="!wizard.ready.value" class="muted block-reason">{{ wizard.blockReason.value }}</span>
        <el-button :disabled="wizard.step.value === 0" @click="wizard.step.value -= 1">上一步</el-button>
        <el-button v-if="wizard.step.value < 5" type="primary" @click="wizard.step.value += 1">下一步</el-button>
        <el-button v-else type="primary" :loading="wizard.busy.value" :disabled="!wizard.ready.value" @click="submitWizard">下发任务</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; }
.path-group { margin-bottom: 10px; }
.path-group .log { max-height: 180px; overflow: auto; }
.type-picker { display: flex; flex-direction: column; gap: 10px; align-items: stretch; }
.type-picker :deep(.el-radio) { margin-right: 0; height: auto; padding: 10px 14px; white-space: normal; }
.type-picker :deep(.el-radio__label) { white-space: normal; line-height: 1.5; }
.type-label { font-weight: 600; }
.type-hint { margin-top: 2px; }
.steps { margin: 6px 0; padding-left: 20px; font-size: 12px; line-height: 1.8; color: var(--soc-text-dim); }
.block-reason { margin-right: 12px; }
.host-block { border: 1px solid var(--soc-border); border-radius: 8px; padding: 10px 12px; margin-bottom: 10px; }
.host-title { font-weight: 600; margin-bottom: 8px; }
.detail { padding: 6px 12px; font-size: 12px; line-height: 1.8; color: var(--soc-text-dim); word-break: break-all; }
.section-title { font-weight: 600; margin: 14px 0 8px; }
.wrap { overflow-wrap: anywhere; }
.log { background: var(--soc-panel-2); border: 1px solid var(--soc-border); border-radius: 6px;
       padding: 10px; font-size: 12px; max-height: 260px; overflow: auto; white-space: pre-wrap; }
:deep(.el-table__row) { cursor: pointer; }
</style>
