<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import StatusBadge from '../components/StatusBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listProbes, registerProbe, analyzeProbe, getProbeTasks, type Probe } from '../api/probes'
import type { Task } from '../types/task'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Probe[]>([])
const total = ref(0)
const form = ref({ name: '', hostname: '', ip_address: '' })
const tasks = ref<Task[]>([])
const drawer = ref(false)
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })

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

async function register(): Promise<void> {
  try {
    await registerProbe({ ...form.value, metadata: {} })
    ElMessage.success('探针已注册')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function analyze(row: Probe): Promise<void> {
  try {
    await analyzeProbe(row.id)
    ElMessage.success('已触发资产分析')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function open(row: Probe): Promise<void> {
  try {
    tasks.value = await getProbeTasks(row.id)
    drawer.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }
onMounted(load)
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-input v-model="form.name" placeholder="名称" />
      <el-input v-model="form.hostname" placeholder="主机名" />
      <el-input v-model="form.ip_address" placeholder="IP" />
      <el-button type="primary" @click="register">注册</el-button>
      <el-input v-model="filters.search" placeholder="搜索" clearable @keyup.enter="reset" />
      <el-select v-model="filters.status" placeholder="状态" clearable><el-option v-for="item in ['online', 'offline']" :key="item" :label="item" :value="item" /></el-select>
      <el-button @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="hostname" label="主机名" />
      <el-table-column prop="ip_address" label="IP" />
      <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
      <el-table-column label="Last Seen" width="160"><template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template></el-table-column>
      <el-table-column label="操作" width="180"><template #default="{ row }"><el-button link type="primary" @click="analyze(row)">分析资产</el-button><el-button link @click="open(row)">历史任务</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="探针历史任务" size="48%"><el-table :data="tasks" size="small"><el-table-column prop="id" label="ID" /><el-table-column prop="kind" label="类型" /><el-table-column prop="status" label="状态" /><el-table-column prop="current_stage" label="阶段" /></el-table></el-drawer>
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
