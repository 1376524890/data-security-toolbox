<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import StatusBadge from '../components/StatusBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listTasks } from '../api/tasks'
import type { Task } from '../types/task'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Task[]>([])
const total = ref(0)
const selected = ref<Task | null>(null)
const drawer = ref(false)
const filters = reactive({ status: '', kind: '', search: '', page: 1, page_size: 50 })
let timer = 0

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listTasks({ ...filters })
    items.value = result.items
    total.value = result.total
    selected.value = items.value.find((item) => item.id === selected.value?.id) || selected.value
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function startPolling(): void {
  timer = window.setInterval(() => {
    if (document.hidden) return
    if (items.value.some((item) => item.status === 'Running' || item.status === 'Pending')) load()
  }, 2000)
}

function open(row: Task): void { selected.value = row; drawer.value = true }
function reset(): void { filters.page = 1; load() }

onMounted(() => { load(); startPolling() })
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-select v-model="filters.status" placeholder="状态" clearable><el-option v-for="item in ['Pending', 'Running', 'Success', 'Failed']" :key="item" :label="item" :value="item" /></el-select>
      <el-select v-model="filters.kind" placeholder="类型" clearable><el-option v-for="item in ['pcap', 'metadata', 'assets']" :key="item" :label="item" :value="item" /></el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column prop="id" label="ID" width="70" />
      <el-table-column prop="kind" label="类型" />
      <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
      <el-table-column label="进度" width="180"><template #default="{ row }"><el-progress :percentage="row.progress" /></template></el-table-column>
      <el-table-column prop="current_stage" label="阶段" />
      <el-table-column label="Created" width="160"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
      <el-table-column label="Started" width="160"><template #default="{ row }">{{ formatDateTime(row.started_at) }}</template></el-table-column>
      <el-table-column prop="error" label="Error" />
      <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="open(row)">详情</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="任务详情" size="42%">
      <template v-if="selected">
        <el-descriptions :column="2" border><el-descriptions-item label="ID">{{ selected.id }}</el-descriptions-item><el-descriptions-item label="类型">{{ selected.kind }}</el-descriptions-item><el-descriptions-item label="状态"><StatusBadge :value="selected.status" /></el-descriptions-item><el-descriptions-item label="进度">{{ selected.progress }}%</el-descriptions-item></el-descriptions>
        <el-divider content-position="left">Pipeline</el-divider>
        <el-steps direction="vertical" :active="selected.progress > 90 ? 5 : 3">
          <el-step title="Upload" description="上传阶段" />
          <el-step title="Parsing" description="解析阶段" />
          <el-step title="Detection" description="检测引擎" />
          <el-step title="Risk" description="风险评分" />
          <el-step title="Incident" description="事件关联" />
        </el-steps>
        <el-divider content-position="left">日志</el-divider>
        <pre class="log">{{ selected.log || '暂无日志' }}</pre>
        <el-alert v-if="selected.error" type="error" :closable="false" :title="selected.error" />
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.pagination { margin-top: 14px; justify-content: flex-end; }
.log { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; max-height: 300px; overflow: auto; }
</style>
