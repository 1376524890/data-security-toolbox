<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { listProbes, deleteProbe, analyzeProbe, queueProbeScan, getProbeTasks, type Probe } from '../../api/probes'
import { useAuthStore } from '../../stores/auth'
import type { Task } from '../../types/task'
import TaskActions from '../../components/common/TaskActions.vue'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const auth = useAuthStore()
const deletingId = ref<number | null>(null)
const error = ref('')
const items = ref<Probe[]>([])
const total = ref(0)
const detail = ref<Probe | null>(null)
const tasks = ref<Task[]>([])
const drawer = ref(false)
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })
const router = useRouter()
const scanDialog = ref(false)
const scanProbe = ref<Probe | null>(null)
const scanTargets = ref('')
const scanPorts = ref('22,80,443,445,3306,5432,6379,8080')
const removeDialog = ref(false)
const removeTarget = ref<Probe | null>(null)
const removal = reactive({
  remote: true,
  host: '',
  port: 22,
  username: 'root',
  auth_type: 'password' as 'password' | 'private_key',
  password: '',
  private_key: '',
  key_passphrase: '',
  keep_data: false,
  keep_user: false,
  remove_user: false,
})

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索名称/IP', placeholder: '搜索名称 / 主机 / IP', width: '240px' },
  { key: 'status', label: '状态', type: 'select', options: ['online', 'degraded', 'offline', 'auth_error'].map((v) => ({ label: v, value: v })), width: '120px' },
]

function metadata(probe: Probe): Record<string, unknown> {
  return (probe.metadata as Record<string, unknown>) || {}
}
function interfaces(probe: Probe): {name:string; is_up:boolean; addresses:{address:string; family:string}[]}[] {
  return (metadata(probe).interfaces as {name:string; is_up:boolean; addresses:{address:string; family:string}[]}[]) || []
}
function cpu(probe: Probe): string { return String(metadata(probe).cpu_percent ?? '—') + '%' }
function mem(probe: Probe): string { const m = metadata(probe).memory_percent; return m != null ? String(m) + '%' : '—' }

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listProbes({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Probe): Promise<void> {
  detail.value = row
  drawer.value = true
  try {
    tasks.value = await getProbeTasks(row.id)
  } catch { tasks.value = [] }
}

async function runAnalyze(row: Probe): Promise<void> {
  try {
    const task = await analyzeProbe(row.id)
    ElMessage.success(`已触发分析任务 #${task.id}`)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function remove(row: Probe): Promise<void> {
  removeTarget.value = row
  // Uninstalling is the default because deleting the record alone leaves a
  // live probe on the host that re-registers on its next heartbeat.
  removal.remote = true
  removal.host = row.ip_address && row.ip_address !== '0.0.0.0' ? row.ip_address : ''
  removal.port = 22
  removal.username = 'root'
  removal.auth_type = 'password'
  removal.password = ''
  removal.private_key = ''
  removal.key_passphrase = ''
  removal.keep_data = false
  removal.keep_user = false
  removal.remove_user = false
  removeDialog.value = true
}

async function submitRemove(): Promise<void> {
  const row = removeTarget.value
  if (!row || deletingId.value !== null) return
  if (removal.remote) {
    if (!removal.host.trim()) { ElMessage.warning('请填写目标主机地址'); return }
    if (!removal.username.trim()) { ElMessage.warning('请填写 SSH 用户名'); return }
    if (removal.auth_type === 'password' && !removal.password) { ElMessage.warning('请填写 SSH 密码'); return }
    if (removal.auth_type === 'private_key' && !removal.private_key.trim()) { ElMessage.warning('请粘贴 SSH 私钥'); return }
  }
  deletingId.value = row.id
  try {
    const result = await deleteProbe(row.id, removal.remote ? {
      remove_remote: true,
      host: removal.host.trim(),
      port: Number(removal.port) || 22,
      username: removal.username.trim(),
      auth_type: removal.auth_type,
      password: removal.auth_type === 'password' ? removal.password : undefined,
      private_key: removal.auth_type === 'private_key' ? removal.private_key : undefined,
      key_passphrase: removal.auth_type === 'private_key' ? removal.key_passphrase || undefined : undefined,
      keep_data: removal.keep_data,
      keep_user: removal.keep_user,
      remove_user: removal.remove_user,
    } : undefined)
    if (detail.value?.id === row.id) { drawer.value = false; detail.value = null; tasks.value = [] }
    if (items.value.length === 1 && filters.page > 1) filters.page -= 1
    removeDialog.value = false
    ElMessage.success(result?.deployment_id
      ? `已下发卸载任务 #${result.deployment_id}：主机清理完成后平台记录会自动移除，进度见「下发记录」`
      : '探针记录已删除，目标主机未被改动')
    await load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally { deletingId.value = null }
}

function openScan(row: Probe): void {
  scanProbe.value = row
  scanTargets.value = row.ip_address && row.ip_address !== '0.0.0.0' ? row.ip_address : ''
  scanDialog.value = true
}

async function submitScan(): Promise<void> {
  if (!scanProbe.value) return
  const targets = scanTargets.value.split(/[\s,]+/).map(v => v.trim()).filter(Boolean)
  const ports = [...new Set(scanPorts.value.split(/[\s,]+/).map(Number).filter(v => Number.isInteger(v) && v >= 1 && v <= 65535))]
  if (!targets.length || !ports.length) { ElMessage.warning('请填写明确的 IP/CIDR 目标和端口'); return }
  try {
    const task = await queueProbeScan(scanProbe.value.id, { targets, ports })
    ElMessage.success(`探针扫描任务 #${task.id} 已入队`)
    scanDialog.value = false
  } catch (err) { ElMessage.error(err instanceof Error ? err.message : String(err)) }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions><el-button @click="router.push('/probe-deployments')">下发记录</el-button><el-button type="primary" @click="router.push({ path: '/probe-deployments', query: { register: '1' } })">注册探针</el-button></template>
    </FilterBar>
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="hostname" label="主机" min-width="120" />
        <el-table-column prop="ip_address" label="IP" width="140" />
        <el-table-column label="网卡 / 地址" min-width="220"><template #default="{row}"><div v-for="nic in interfaces(row)" :key="nic.name">{{nic.name}}：{{nic.addresses.map(a=>a.address).join(', ') || '无 IP'}} {{nic.is_up ? '' : '（未启用）'}}</div><span v-if="!interfaces(row).length">等待探针上报</span></template></el-table-column>
        <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        <el-table-column label="CPU" width="80"><template #default="{ row }">{{ cpu(row) }}</template></el-table-column>
        <el-table-column label="内存" width="90"><template #default="{ row }">{{ mem(row) }}</template></el-table-column>
        <el-table-column label="最近上报" width="160"><template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template></el-table-column>
        <el-table-column label="操作" width="270" fixed="right"><template #default="{ row }"><el-button size="small" @click.stop="runAnalyze(row)">分析</el-button><el-button size="small" @click.stop="openScan(row)">扫描</el-button><el-button size="small" type="primary" @click.stop="open(row)">详情</el-button><el-button v-if="auth.user?.role === 'admin'" size="small" type="danger" :loading="deletingId === row.id" :disabled="deletingId !== null" @click.stop="remove(row)">删除</el-button></template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="探针详情" width="60%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="名称">{{ detail.name }}</el-descriptions-item>
          <el-descriptions-item label="主机">{{ detail.hostname }}</el-descriptions-item>
          <el-descriptions-item label="IP"><span class="mono">{{ detail.ip_address }}</span></el-descriptions-item>
          <el-descriptions-item label="状态"><StatusBadge :value="detail.status" /></el-descriptions-item>
          <el-descriptions-item label="CPU">{{ cpu(detail) }}</el-descriptions-item>
          <el-descriptions-item label="内存">{{ mem(detail) }}</el-descriptions-item>
          <el-descriptions-item label="最近上报">{{ formatDateTime(detail.last_seen) }}</el-descriptions-item>
        </el-descriptions>
        <div class="sec-title" style="margin-top: 14px">探针元数据</div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item v-for="(v, k) in detail.metadata" :key="k" :label="k"><span class="mono">{{ v }}</span></el-descriptions-item>
        </el-descriptions>
        <div class="sec-title" style="margin-top: 14px">关联任务</div>
        <el-table :data="tasks" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="kind" label="类型" width="110" />
          <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
          <el-table-column prop="current_stage" label="阶段" min-width="140" />
          <el-table-column label="操作" width="110"><template #default="{ row }"><TaskActions :task="row" @changed="detail && open(detail)" /></template></el-table-column>
        </el-table>
      </template>
    </DetailDrawer>
    <el-dialog v-model="scanDialog" title="下发探针侧资产扫描" width="560px">
      <el-alert title="扫描在探针所在主机执行。请仅填写已获授权的 IP 或 CIDR，单次最多 1024 台主机、256 个端口。" type="warning" :closable="false" />
      <el-form label-width="90px" style="margin-top:16px">
        <el-form-item label="目标"><el-input v-model="scanTargets" type="textarea" :rows="3" placeholder="192.168.1.10 或 192.168.1.0/24；多个目标用逗号或换行分隔" /></el-form-item>
        <el-form-item label="TCP 端口"><el-input v-model="scanPorts" placeholder="22,80,443,3306" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="scanDialog=false">取消</el-button><el-button type="primary" @click="submitScan">下发扫描</el-button></template>
    </el-dialog>
    <el-dialog v-model="removeDialog" title="删除探针" width="640px" :close-on-click-modal="false" :close-on-press-escape="deletingId === null" :show-close="deletingId === null">
      <el-alert title="同时卸载（推荐）：平台通过 SSH 停止服务、删除 systemd 单元和探针在主机上产生的全部生产文件，清理成功后再删除平台记录，并保留“删除了哪些文件”的审计结果。" type="success" :closable="false" />
      <el-alert v-if="!removal.remote" title="仅删除平台记录：主机上的探针进程、systemd 单元和 /opt/data-security-toolbox、/var/lib/data-security-toolbox 等生产文件都不会被清理，探针会再次注册。" type="error" :closable="false" style="margin-top:8px" />
      <el-form :disabled="deletingId !== null" label-width="110px" style="margin-top:16px">
        <el-form-item label="探针">{{ removeTarget?.name }}（{{ removeTarget?.ip_address || '未知 IP' }}）</el-form-item>
        <el-form-item label="卸载主机探针"><el-switch v-model="removal.remote" active-text="清理主机文件后再删除记录" /></el-form-item>
        <template v-if="removal.remote">
          <el-form-item label="目标主机" required><el-input v-model="removal.host" placeholder="192.168.1.10" /></el-form-item>
          <el-form-item label="SSH 端口"><el-input-number v-model="removal.port" :min="1" :max="65535" /></el-form-item>
          <el-form-item label="用户名" required><el-input v-model="removal.username" placeholder="root" /></el-form-item>
          <el-form-item label="认证方式"><el-radio-group v-model="removal.auth_type"><el-radio-button value="password">密码</el-radio-button><el-radio-button value="private_key">私钥</el-radio-button></el-radio-group></el-form-item>
          <el-form-item v-if="removal.auth_type === 'password'" label="密码" required><el-input v-model="removal.password" type="password" show-password /></el-form-item>
          <template v-else>
            <el-form-item label="私钥" required><el-input v-model="removal.private_key" type="textarea" :rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" /></el-form-item>
            <el-form-item label="密钥口令"><el-input v-model="removal.key_passphrase" type="password" show-password /></el-form-item>
          </template>
          <el-form-item label="保留项">
            <el-checkbox v-model="removal.keep_data">保留采集数据（采集分段与缓存）</el-checkbox>
            <el-checkbox v-model="removal.keep_user">保留 dstprobe 系统账号</el-checkbox>
            <el-checkbox v-model="removal.remove_user">强制删除 dstprobe 账号</el-checkbox>
          </el-form-item>
        </template>
      </el-form>
      <el-alert v-if="removal.remote" title="凭据仅用于本次卸载，任务结束后平台立即销毁、不留存。dstprobe 系统账号仅在安装时确由本探针创建的情况下才会删除，否则自动保留。" type="info" :closable="false" />
      <template #footer>
        <el-button :disabled="deletingId !== null" @click="removeDialog = false">取消</el-button>
        <el-button type="danger" :loading="deletingId !== null" @click="submitRemove">{{ removal.remote ? '卸载并删除记录' : '仅删除记录' }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
