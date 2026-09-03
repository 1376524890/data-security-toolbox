<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listTasks, getTask, type TaskQuery } from '../../api/tasks'
import type { Task } from '../../types/task'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Task[]>([])
const total = ref(0)
const detail = ref<Task | null>(null)
const drawer = ref(false)
const filters = reactive<TaskQuery>({ search: '', status: '', kind: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索类型/阶段', placeholder: '搜索类型 / 阶段 / 错误', width: '240px' },
  { key: 'status', label: '状态', type: 'select', options: ['Pending', 'Running', 'Success', 'Failed'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'kind', label: '类型', type: 'select', options: ['pcap', 'assets', 'metadata'].map((v) => ({ label: v, value: v })), width: '110px' },
]

function duration(task: Task): string {
  if (!task.started_at) return '—'
  const start = new Date(task.started_at).getTime()
  const end = task.finished_at ? new Date(task.finished_at).getTime() : Date.now()
  const sec = Math.max(0, Math.round((end - start) / 1000))
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listTasks({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Task): Promise<void> {
  try {
    detail.value = await getTask(row.id)
    drawer.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="kind" label="类型" width="110" />
        <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        <el-table-column prop="current_stage" label="阶段" min-width="160" show-overflow-tooltip />
        <el-table-column label="进度" width="120"><template #default="{ row }"><el-progress :percentage="row.progress" :stroke-width="6" /></template></el-table-column>
        <el-table-column label="时长" width="90"><template #default="{ row }">{{ duration(row) }}</template></el-table-column>
        <el-table-column label="创建时间" width="160"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="任务详情" width="60%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="ID"><span class="mono">#{{ detail.id }}</span></el-descriptions-item>
          <el-descriptions-item label="类型">{{ detail.kind }}</el-descriptions-item>
          <el-descriptions-item label="状态"><StatusBadge :value="detail.status" /></el-descriptions-item>
          <el-descriptions-item label="进度">{{ detail.progress }}%</el-descriptions-item>
          <el-descriptions-item label="阶段">{{ detail.current_stage }}</el-descriptions-item>
          <el-descriptions-item label="时长">{{ duration(detail) }}</el-descriptions-item>
        </el-descriptions>
        <div class="sec-title" style="margin-top: 14px">日志</div>
        <pre class="task-log mono">{{ detail.log || '—' }}</pre>
        <div class="sec-title" style="margin-top: 14px">载荷</div>
        <JsonViewer :value="detail.payload" title="载荷 JSON" :height="200" />
        <div class="sec-title" style="margin-top: 14px">结果</div>
        <JsonViewer :value="detail.result" title="结果 JSON" :height="200" />
        <div v-if="detail.error" class="sec-title" style="margin-top: 14px; color: var(--soc-danger)">错误: {{ detail.error }}</div>
      </template>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
.task-log { background: #0e1626; border: 1px solid var(--soc-border); border-radius: 6px; padding: 10px; font-size: 12px; max-height: 200px; overflow: auto; white-space: pre-wrap; }
</style>
