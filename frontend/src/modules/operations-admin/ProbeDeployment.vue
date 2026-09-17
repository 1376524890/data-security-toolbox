<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  createDeployment,
  deleteDeployment,
  getDeployment,
  listDeployments,
  preflight,
  retryDeployment,
} from '../../api/probeDeployments'
import type { CreateDeploymentPayload, ProbeDeployment, ProbeDeploymentDetail, PreflightResult, RemovalAudit } from '../../types/probeDeployment'
import StateBox from '../../components/common/StateBox.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { formatDateTime } from '../../utils/format'

const route = useRoute()
const router = useRouter()
const retryId = ref<number | null>(null)
let pollTimer: ReturnType<typeof setTimeout> | undefined
let disposed = false
const loading = ref(true)
const error = ref('')
const items = ref<ProbeDeployment[]>([])
const total = ref(0)
const detail = ref<ProbeDeploymentDetail | null>(null)
const drawer = ref(false)
const dialog = ref(false)
const submitting = ref(false)
const preflightResult = ref<PreflightResult | null>(null)
const preflightLoading = ref(false)
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })
const form = reactive({
  backend_url: '',
  name: '',
  host: '',
  port: 22,
  username: 'root',
  auth_type: 'password' as 'password' | 'private_key',
  password: '',
  private_key: '',
  key_passphrase: '',
  profile: 'standard' as 'lite' | 'standard' | 'sensor',
  data_paths: '',
  data_interval_seconds: 3600,
  data_max_files: 200,
  data_max_depth: 3,
  data_include_databases: true,
})

function idempotencyKey(): string {
  return typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `deploy-${Date.now()}`
}

function payload(): CreateDeploymentPayload {
  return {
    backend_url: form.backend_url.trim() || undefined,
    name: form.name.trim() || `probe-${form.host.trim()}`,
    host: form.host.trim(),
    port: Number(form.port),
    username: form.username.trim(),
    auth_type: form.auth_type,
    password: form.auth_type === 'password' ? form.password : undefined,
    private_key: form.auth_type === 'private_key' ? form.private_key : undefined,
    key_passphrase: form.auth_type === 'private_key' ? form.key_passphrase || undefined : undefined,
    profile: form.profile,
    data_paths: form.data_paths.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean),
    data_interval_seconds: form.data_interval_seconds,
    data_max_files: form.data_max_files,
    data_max_depth: form.data_max_depth,
    data_include_databases: form.data_include_databases,
    idempotency_key: idempotencyKey(),
  }
}

async function load(silent = false): Promise<void> {
  if (!silent) loading.value = true
  error.value = ''
  try {
    const result = await listDeployments({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: ProbeDeployment): Promise<void> {
  drawer.value = true
  try {
    detail.value = await getDeployment(row.id)
  } catch {
    detail.value = null
  }
}

function validate(): boolean {
  if (!form.host.trim() || !form.username.trim()) { ElMessage.warning('请填写目标主机 IP 和用户名'); return false }
  if (!Number.isInteger(form.port) || form.port < 1 || form.port > 65535) { ElMessage.warning('SSH 端口必须为 1–65535'); return false }
  if (form.auth_type === 'password' ? !form.password : !form.private_key) { ElMessage.warning(form.auth_type === 'password' ? '请填写密码' : '请填写私钥'); return false }
  return true
}

async function runPreflight(): Promise<void> {
  if (preflightLoading.value || submitting.value || !validate()) return
  preflightLoading.value = true
  preflightResult.value = null
  try {
    preflightResult.value = await preflight(payload())
    ElMessage.success(`预检完成：${preflightResult.value.compatible ? '兼容' : '不兼容'}`)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    preflightLoading.value = false
  }
}

async function submit(): Promise<void> {
  if (submitting.value || preflightLoading.value || !validate()) return
  submitting.value = true
  try {
    const dep = retryId.value === null ? await createDeployment(payload()) : await retryDeployment(retryId.value, payload())
    ElMessage.success(`下发任务 #${dep.id} 已提交，正在自动安装并等待探针注册和心跳`)
    dialog.value = false
    resetForm()
    await load()
    await open(dep)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    submitting.value = false
  }
}

function retry(row: ProbeDeployment): void {
  resetForm()
  retryId.value = row.id
  Object.assign(form, {
    name: row.name,
    host: row.host,
    port: row.port,
    username: row.username,
    auth_type: row.auth_type,
    profile: row.profile,
    data_paths: (row.data_config?.paths || []).join('\n'),
    data_interval_seconds: row.data_config?.interval_seconds ?? 3600,
    data_max_files: row.data_config?.max_files ?? 200,
    data_max_depth: row.data_config?.max_depth ?? 3,
    data_include_databases: row.data_config?.include_databases ?? true,
  })
  dialog.value = true
}

/** The audit the uninstaller reported, once a removal has something to show. */
function audit(row: ProbeDeployment | ProbeDeploymentDetail | null): RemovalAudit | null {
  if (!row || row.action !== 'uninstall') return null
  const value = row.result as unknown as RemovalAudit
  return value && value.finished_at ? value : null
}

function freed(value: number | undefined): string {
  const bytes = value || 0
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GiB`
}

function auditOk(row: ProbeDeployment | ProbeDeploymentDetail | null): boolean {
  return audit(row)?.ok === true
}

function auditSummary(row: ProbeDeployment | ProbeDeploymentDetail | null): string {
  const value = audit(row)
  if (!value) return ''
  if (value.ok) {
    return `清理成功：删除 ${(value.removed || []).length} 项，释放 ${freed(value.bytes_freed)}（${value.files_freed ?? 0} 个文件）`
  }
  return `清理未完成（退出码 ${value.exit_code ?? '—'}）：${value.reason || '部分内容未能删除，可重试或人工清理'}`
}

/** One row per line of the uninstaller's report, so the console can answer
    "what was actually deleted on that host?". */
function auditRows(row: ProbeDeployment | ProbeDeploymentDetail | null): { label: string; value: string }[] {
  const value = audit(row)
  if (!value) return []
  const rows = [
    { label: '已删除', value: (value.removed || []).join('、') || '无' },
    { label: '本就不存在', value: (value.absent || []).join('、') || '无' },
    { label: '按选项保留', value: (value.kept || []).join('、') || '无' },
    { label: '未能删除', value: (value.failed || []).join('、') || '无' },
    { label: '释放空间', value: `${freed(value.bytes_freed)}（${value.files_freed ?? 0} 个文件）` },
  ]
  if (value.reason) rows.push({ label: '说明', value: value.reason })
  return rows
}

function removalOptionText(row: ProbeDeployment | ProbeDeploymentDetail | null): string {
  const options = row?.removal_options || {}
  const parts = [options.keep_data ? '保留采集数据' : '删除采集数据']
  if (options.remove_user) parts.push('强制删除 dstprobe 账号')
  else if (options.keep_user) parts.push('保留 dstprobe 账号')
  else parts.push('按安装标记决定是否删除账号')
  if (options.delete_record) parts.push('同时删除平台记录')
  return parts.join('；')
}

/** Finished rows are history; only those can leave the history. */
const finishedStatuses = ['ONLINE', 'FAILED', 'CANCELLED', 'REMOVED']
async function dropRecord(row: ProbeDeployment): Promise<void> {
  try {
    await deleteDeployment(row.id)
    if (detail.value?.id === row.id) { drawer.value = false; detail.value = null }
    ElMessage.success('已删除该条记录（未改动目标主机）')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function startRegistration(): void {
  resetForm()
  dialog.value = true
}

async function poll(): Promise<void> {
  await load(true)
  if (!disposed && drawer.value && detail.value) {
    const id = detail.value.id
    try {
      const updated = await getDeployment(id)
      if (!disposed && drawer.value && detail.value?.id === id) detail.value = updated
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    }
  }
  if (!disposed) pollTimer = setTimeout(poll, 3000)
}

function handleRegistrationRoute(): void {
  if (route.query.register === '1') {
    startRegistration()
    const { register, ...query } = route.query
    void router.replace({ query })
  }
}
watch(() => route.query.register, handleRegistrationRoute)

function resetForm(): void {
  retryId.value = null
  Object.assign(form, {
    backend_url: '',
    name: '',
    host: '',
    port: 22,
    username: 'root',
    auth_type: 'password',
    password: '',
    private_key: '',
    key_passphrase: '',
    profile: 'standard',
    data_paths: '',
    data_interval_seconds: 3600,
    data_max_files: 200,
    data_max_depth: 3,
    data_include_databases: true,
  })
  preflightResult.value = null
}

function reset(): void {
  filters.page = 1
  load()
}

onMounted(() => { handleRegistrationRoute(); void poll() })
onUnmounted(() => { disposed = true; clearTimeout(pollTimer) })
</script>

<template>
  <div>
    <div class="toolbar">
      <el-input v-model="filters.search" placeholder="搜索名称 / 主机" clearable style="width: 240px" @keyup.enter="reset" />
      <el-select v-model="filters.status" placeholder="状态" clearable style="width: 160px; margin-left: 8px">
        <el-option v-for="s in ['CREATED', 'CONNECTING', 'PREFLIGHT', 'UPLOADING', 'INSTALLING', 'WAIT_CALLBACK', 'REGISTERED', 'ONLINE', 'REMOVING', 'REMOVED', 'FAILED']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-button @click="reset">查询</el-button>
      <el-button type="primary" style="margin-left: auto" @click="startRegistration">注册探针</el-button>
    </div>

    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="name" label="名称" min-width="140" />
        <el-table-column label="动作" width="90"><template #default="{ row }"><el-tag :type="row.action === 'uninstall' ? 'warning' : 'info'" size="small">{{ row.action === 'uninstall' ? '卸载' : '安装' }}</el-tag></template></el-table-column>
        <el-table-column label="目标" min-width="180"><template #default="{ row }">{{ row.host }}:{{ row.port }}</template></el-table-column>
        <el-table-column label="Profile" width="100"><template #default="{ row }">{{ row.action === 'uninstall' ? '—' : row.profile }}</template></el-table-column>
        <el-table-column label="状态" width="130"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        <el-table-column label="进度" width="120"><template #default="{ row }"><el-progress :percentage="row.progress" :stroke-width="8" /></template></el-table-column>
        <el-table-column label="Probe" width="80"><template #default="{ row }">{{ row.probe_id ?? '—' }}</template></el-table-column>
        <el-table-column label="创建时间" width="160"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="180"><template #default="{ row }"><el-button size="small" type="primary" @click.stop="open(row)">详情</el-button><el-button v-if="row.action === 'install' && row.status === 'FAILED'" size="small" type="warning" @click.stop="retry(row)">重试</el-button><el-button v-else-if="finishedStatuses.includes(row.status)" size="small" type="danger" @click.stop="dropRecord(row)">删除记录</el-button></template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="部署详情" width="60%">
      <template v-if="detail">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="名称">{{ detail.name }}</el-descriptions-item>
          <el-descriptions-item label="动作">{{ detail.action === 'uninstall' ? '卸载探针' : '下发探针' }}</el-descriptions-item>
          <el-descriptions-item label="目标">{{ detail.host }}:{{ detail.port }}</el-descriptions-item>
          <el-descriptions-item label="账户">{{ detail.username }}</el-descriptions-item>
          <el-descriptions-item label="Profile">{{ detail.action === 'uninstall' ? '—' : detail.profile }}</el-descriptions-item>
          <el-descriptions-item v-if="detail.action === 'uninstall'" label="清理选项" :span="2">{{ removalOptionText(detail) }}</el-descriptions-item>
          <el-descriptions-item v-else label="数据资产目录" :span="2">
            <span class="mono">{{ (detail.data_config?.paths || []).length ? (detail.data_config?.paths || []).join('、') : '未配置（可在数据资产页手动采集）' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="状态"><StatusBadge :value="detail.status" /></el-descriptions-item>
          <el-descriptions-item label="Probe ID">{{ detail.probe_id ?? '—' }} <el-button v-if="detail.status === 'ONLINE'" link type="primary" @click="router.push('/probes')">查看探针</el-button></el-descriptions-item>
          <el-descriptions-item label="包版本">{{ detail.package_version || '—' }}</el-descriptions-item>
          <el-descriptions-item label="凭据销毁">{{ detail.credential_destroyed ? '是' : '否' }}</el-descriptions-item>
        </el-descriptions>
        <el-alert v-if="detail.error_message" :title="`${detail.error_code}: ${detail.error_message}`" type="error" :closable="false" style="margin-top: 12px" />
        <template v-if="auditRows(detail).length">
          <div class="sec-title" style="margin-top: 14px">主机清理结果</div>
          <el-alert :title="auditSummary(detail)" :type="auditOk(detail) ? 'success' : 'error'" :closable="false" />
          <el-descriptions :column="1" border size="small" style="margin-top: 8px">
            <el-descriptions-item v-for="row in auditRows(detail)" :key="row.label" :label="row.label"><span class="mono">{{ row.value }}</span></el-descriptions-item>
          </el-descriptions>
        </template>
        <div class="sec-title" style="margin-top: 14px">进度事件</div>
        <el-timeline>
          <el-timeline-item v-for="e in detail.events" :key="e.id" :timestamp="formatDateTime(e.created_at)">{{ e.stage }} — {{ e.message }}</el-timeline-item>
        </el-timeline>
        <div v-if="detail.action === 'install' && detail.preflight_result" class="sec-title" style="margin-top: 14px">预检结果</div>
        <el-table v-if="detail.action === 'install' && detail.preflight_result" :data="(detail.preflight_result.checks as any[])" size="small">
          <el-table-column prop="name" label="检查" />
          <el-table-column prop="actual" label="实际" />
          <el-table-column prop="required" label="要求" />
          <el-table-column label="通过" width="80"><template #default="{ row }"><el-tag :type="row.pass ? 'success' : 'danger'">{{ row.pass ? '是' : '否' }}</el-tag></template></el-table-column>
        </el-table>
      </template>
    </DetailDrawer>

    <el-dialog v-model="dialog" :title="retryId === null ? '注册探针 · 自动下发' : '重新下发探针'" :close-on-click-modal="false" :close-on-press-escape="!submitting" :show-close="!submitting" width="640px" @closed="resetForm">
      <el-alert title="填写目标 Linux 主机 IP、SSH 端口、用户名和密码后，平台自动预检、下发、安装并等待注册及首次心跳。账户需为 root 或具备免密 sudo 权限。" type="warning" :closable="false" />
      <el-form :disabled="submitting || preflightLoading" label-width="120px" style="margin-top: 16px">
        <el-form-item label="探针名称"><el-input v-model="form.name" placeholder="可选，默认按目标 IP 命名" /></el-form-item>
        <el-form-item label="目标主机 IP" required><el-input v-model="form.host" :disabled="retryId !== null" placeholder="192.168.1.10" /></el-form-item>
        <el-form-item label="SSH 端口"><el-input-number v-model="form.port" :min="1" :max="65535" /></el-form-item>
        <el-form-item label="用户名" required><el-input v-model="form.username" placeholder="root" /></el-form-item>
        <el-form-item label="认证方式"><el-radio-group v-model="form.auth_type"><el-radio-button value="password">密码</el-radio-button><el-radio-button value="private_key">私钥</el-radio-button></el-radio-group></el-form-item>
        <el-form-item v-if="form.auth_type === 'password'" label="密码" required><el-input v-model="form.password" type="password" show-password /></el-form-item>
        <el-form-item v-if="form.auth_type === 'private_key'" label="私钥"><el-input v-model="form.private_key" type="textarea" :rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" /></el-form-item>
        <el-form-item v-if="form.auth_type === 'private_key'" label="密钥口令"><el-input v-model="form.key_passphrase" type="password" show-password /></el-form-item>
        <el-form-item label="平台回连地址"><el-input v-model="form.backend_url" placeholder="http://平台任一可达网卡IP:8000（留空使用平台默认地址）" /><div style="color:var(--soc-text-muted);font-size:12px">可指定平台任一网卡的 IPv4、IPv6（如 http://[IPv6]:8000）或域名；预检会从探针主机验证连通性。默认采集所有网卡。</div></el-form-item>
        <el-form-item label="Profile"><el-select v-model="form.profile"><el-option value="lite" label="Lite（仅心跳/资产）" /><el-option value="standard" label="Standard（有界采集）" /><el-option value="sensor" label="Sensor（持续采集）" /></el-select></el-form-item>
        <el-form-item label="数据资产目录">
          <el-input v-model="form.data_paths" type="textarea" :rows="3" placeholder="每行一个绝对路径，例如：&#10;/srv/data&#10;/var/www/uploads&#10;留空则部署后不自动采集，可稍后在「数据资产」页手动触发" />
          <div style="color:var(--soc-text-muted);font-size:12px">部署后探针会枚举这些目录（文件名、字段、敏感类目统计，不上传原始数据），也可由平台随时下发采集任务。</div>
        </el-form-item>
        <el-form-item label="采集周期"><el-input-number v-model="form.data_interval_seconds" :min="60" :max="86400" :step="300" /> <span style="margin-left:8px;color:var(--soc-text-muted);font-size:12px">秒</span></el-form-item>
        <el-form-item label="文件上限 / 深度">
          <el-input-number v-model="form.data_max_files" :min="1" :max="2000" />
          <el-input-number v-model="form.data_max_depth" :min="0" :max="8" style="margin-left:8px" />
        </el-form-item>
        <el-form-item label="数据库服务"><el-switch v-model="form.data_include_databases" active-text="登记本机监听的数据库服务" /></el-form-item>
        <el-form-item label="预检"><el-button :loading="preflightLoading" @click="runPreflight">执行预检</el-button></el-form-item>
      </el-form>
      <el-alert v-if="preflightResult" :title="`预检：${preflightResult.compatible ? '兼容' : '不兼容'} | OS ${preflightResult.os} | ${preflightResult.arch} | 分数 ${preflightResult.capability_score}`" :type="preflightResult.compatible ? 'success' : 'warning'" :closable="false" />
      <template #footer><el-button :disabled="submitting || preflightLoading" @click="dialog = false">取消</el-button><el-button type="primary" :loading="submitting" :disabled="preflightLoading" @click="submit">注册并自动下发</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
.toolbar { display: flex; align-items: center; margin-bottom: 12px; }
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
