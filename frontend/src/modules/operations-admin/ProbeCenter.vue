<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listProbes, registerProbe, analyzeProbe, getProbeTasks, type Probe } from '../../api/probes'
import type { Task } from '../../types/task'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Probe[]>([])
const total = ref(0)
const detail = ref<Probe | null>(null)
const tasks = ref<Task[]>([])
const drawer = ref(false)
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索名称/IP', placeholder: '搜索名称 / 主机 / IP', width: '240px' },
  { key: 'status', label: '状态', type: 'select', options: ['online', 'degraded', 'offline', 'auth_error'].map((v) => ({ label: v, value: v })), width: '120px' },
]

function metadata(probe: Probe): Record<string, unknown> {
  return (probe.metadata as Record<string, unknown>) || {}
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

async function handleRegister(): Promise<void> {
  try {
    const res = await registerProbe({ name: `probe-${Date.now()}`, hostname: 'manual', ip_address: '0.0.0.0' })
    ElMessage.success(`探针已注册 #${res.id}（token 见响应）`)
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions><el-button type="primary" @click="handleRegister">注册探针</el-button></template>
    </FilterBar>
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="hostname" label="主机" min-width="120" />
        <el-table-column prop="ip_address" label="IP" width="140" />
        <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        <el-table-column label="CPU" width="80"><template #default="{ row }">{{ cpu(row) }}</template></el-table-column>
        <el-table-column label="内存" width="90"><template #default="{ row }">{{ mem(row) }}</template></el-table-column>
        <el-table-column label="最近上报" width="160"><template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template></el-table-column>
        <el-table-column label="操作" width="120"><template #default="{ row }"><el-button size="small" @click.stop="runAnalyze(row)">分析</el-button><el-button size="small" type="primary" @click.stop="open(row)">详情</el-button></template></el-table-column>
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
        </el-table>
      </template>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
