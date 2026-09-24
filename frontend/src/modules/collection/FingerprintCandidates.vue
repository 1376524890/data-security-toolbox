<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import StateBox from '../../components/common/StateBox.vue'
import { apiGet, apiPost } from '../../api/client'
import { useAutoRefresh } from '../../composables/useAutoRefresh'
import { useTableSort, sortRows } from '../../composables/useTableSort'

// A scan can propose a high-risk file's SHA256, but a proposal is not a rule:
// nothing here takes part in detection until an operator accepts it. Accepting
// puts the hash into a policy group named after the task that found it, so the
// default policy is never touched.
interface Candidate {
  sha256: string; path: string; name: string; source_name: string
  level: string; severity: string; task_id: number | null
  status: 'candidate' | 'accepted' | 'ignored'; group_name: string; first_seen: string
}

const loading = ref(true)
const error = ref('')
const items = ref<Candidate[]>([])
const busy = ref('')
// One unpaged response, so filter and sort in the browser.
const filters = reactive({ search: '', status: '' })
const { sort, onSortChange } = useTableSort()
const visibleItems = computed(() => {
  const needle = filters.search.trim().toLowerCase()
  const rows = items.value.filter((row) => {
    if (filters.status && row.status !== filters.status) return false
    if (!needle) return true
    return [row.name, row.path, row.source_name, row.sha256]
      .some((field) => String(field || '').toLowerCase().includes(needle))
  })
  return sortRows(rows, sort.prop, sort.order, (row, prop) => (row as unknown as Record<string, unknown>)[prop])
})

async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
  if (!silent) { loading.value = true; error.value = '' }
  try {
    items.value = (await apiGet<{ items: Candidate[] }>('/fingerprint-candidates')).items
    error.value = ''
  } catch (err) {
    if (!silent) error.value = String(err)
  } finally {
    if (!silent) loading.value = false
  }
}

// Candidates are only added by a finished scan, so a minute is enough.
useAutoRefresh(load, { intervalMs: 60000 })

async function accept(row: Candidate): Promise<void> {
  busy.value = row.sha256
  try {
    const result = await apiPost<{ group_name: string }>(`/fingerprint-candidates/${row.sha256}/accept`, {})
    ElMessage.success(`已加入规则集「${result.group_name}」`)
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  } finally {
    busy.value = ''
  }
}

async function ignore(row: Candidate): Promise<void> {
  busy.value = row.sha256
  try {
    await apiPost(`/fingerprint-candidates/${row.sha256}/ignore`, {})
    await load()
  } catch (err) {
    ElMessage.error(String(err))
  } finally {
    busy.value = ''
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <strong>候选指纹</strong>
      <span class="muted">扫描发现的高危文件（Critical/High，带完整 SHA256）会在这里候选；确认后才成为规则</span>
      <div class="toolbar-spacer" />
      <el-button @click="load()">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="toolbar" style="margin-bottom: 10px">
        <el-input v-model="filters.search" clearable placeholder="文件 / 路径 / 来源 / SHA256" style="width: 280px" />
        <el-select v-model="filters.status" clearable placeholder="全部状态" style="width: 140px">
          <el-option label="待确认" value="candidate" />
          <el-option label="已加入" value="accepted" />
          <el-option label="已忽略" value="ignored" />
        </el-select>
        <span class="muted">显示 {{ visibleItems.length }} / {{ items.length }} 条</span>
      </div>
      <el-table :data="visibleItems" size="small" max-height="520"
                empty-text="还没有候选；下发一次扫描并命中高危文件后会出现" @sort-change="onSortChange">
        <el-table-column prop="name" label="文件" min-width="240" show-overflow-tooltip sortable="custom">
          <template #default="{ row }">
            <strong>{{ row.name || row.sha256.slice(0, 12) }}</strong>
            <div class="muted">{{ row.path }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="source_name" label="来源" min-width="150" show-overflow-tooltip sortable="custom" />
        <el-table-column label="评级" width="130">
          <template #default="{ row }">
            <el-tag size="small" :type="row.severity === 'Critical' ? 'danger' : 'warning'">
              {{ row.level }} {{ row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="SHA256" min-width="200" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.sha256 }}</span></template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="150" sortable="custom">
          <template #default="{ row }">
            <el-tag v-if="row.status === 'accepted'" size="small" type="success">已加入 {{ row.group_name }}</el-tag>
            <el-tag v-else-if="row.status === 'ignored'" size="small" type="info">已忽略</el-tag>
            <el-tag v-else size="small" type="warning">待确认</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="task_id" label="任务" width="100" sortable="custom">
          <template #default="{ row }">{{ row.task_id ? `#${row.task_id}` : '—' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <template v-if="row.status === 'candidate'">
              <el-button link type="primary" size="small" :loading="busy === row.sha256"
                         @click="accept(row)">一键加入</el-button>
              <el-button link type="info" size="small" :loading="busy === row.sha256"
                         @click="ignore(row)">忽略</el-button>
            </template>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
      </el-table>
    </StateBox>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; }
.mono { font-family: var(--soc-font-mono); font-size: 12px; }
</style>
