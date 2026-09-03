<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listReports, generateReport, type Report } from '../../api/reports'
import { downloadUrl } from '../../api/client'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import { formatDateTime, formatBytes } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Report[]>([])
const total = ref(0)
const filters = reactive({ report_type: '', format: '', search: '', page: 1, page_size: 50 })
const generating = ref(false)
const form = reactive({ title: '数据安全检测报告', report_type: 'security', format: 'html' })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索标题', placeholder: '搜索标题', width: '220px' },
  { key: 'report_type', label: '类型', type: 'select', options: ['security', 'compliance', 'data'].map((v) => ({ label: v, value: v })), width: '120px' },
  { key: 'format', label: '格式', type: 'select', options: ['pdf', 'html'].map((v) => ({ label: v, value: v })), width: '110px' },
]

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listReports({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function handleGenerate(): Promise<void> {
  generating.value = true
  try {
    await generateReport({ ...form })
    ElMessage.success('报告已生成')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    generating.value = false
  }
}

function download(row: Report): void { window.open(downloadUrl(`/reports/${row.id}/download`), '_blank') }
function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <div class="soc-card" style="margin-bottom: 12px">
      <div class="soc-card-title"><span class="dot" />生成报告</div>
      <div class="toolbar" style="margin-bottom: 0">
        <el-input v-model="form.title" placeholder="报告标题" style="width: 260px" />
        <el-select v-model="form.report_type" style="width: 140px"><el-option label="安全" value="security" /><el-option label="合规" value="compliance" /><el-option label="数据" value="data" /></el-select>
        <el-select v-model="form.format" style="width: 110px"><el-option label="PDF" value="pdf" /><el-option label="HTML" value="html" /></el-select>
        <el-button type="primary" :loading="generating" @click="handleGenerate">生成</el-button>
      </div>
    </div>

    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small">
        <el-table-column prop="title" label="标题" min-width="220" show-overflow-tooltip />
        <el-table-column prop="report_type" label="类型" width="110" />
        <el-table-column prop="format" label="格式" width="90" />
        <el-table-column label="大小" width="90"><template #default="{ row }">{{ formatBytes(row.size) }}</template></el-table-column>
        <el-table-column label="创建时间" width="160"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="110"><template #default="{ row }"><el-button size="small" @click="download(row)">下载</el-button></template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>
  </div>
</template>
