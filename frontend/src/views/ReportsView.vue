<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { downloadUrl } from '../api/client'
import { listReports, generateReport } from '../api/reports'
import type { Report } from '../api/reports'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const rows = ref<Report[]>([])
const total = ref(0)
const title = ref('数据安全检测报告')
const reportType = ref('security')
const format = ref('pdf')
const page = ref(1)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listReports({ page: page.value, page_size: 50 })
    rows.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function generate(): Promise<void> {
  try {
    await generateReport({ title: title.value, report_type: reportType.value, format: format.value })
    ElMessage.success('报告已生成')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function openReport(id: number): void { window.open(downloadUrl(`/reports/${id}/download`), '_blank') }
onMounted(load)
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-input v-model="title" placeholder="报告标题" />
      <el-select v-model="reportType"><el-option label="Full Security" value="security" /><el-option label="Data Security" value="data" /><el-option label="Network Analysis" value="network" /><el-option label="Incident" value="incident" /><el-option label="Asset Risk" value="asset" /></el-select>
      <el-select v-model="format"><el-option label="PDF" value="pdf" /><el-option label="HTML" value="html" /></el-select>
      <el-button type="primary" @click="generate">生成报告</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!rows.length" />
    <el-table v-else :data="rows" stripe>
      <el-table-column prop="title" label="标题" />
      <el-table-column prop="report_type" label="类型" />
      <el-table-column prop="format" label="格式" />
      <el-table-column label="大小" width="100"><template #default="{ row }">{{ row.size }} B</template></el-table-column>
      <el-table-column label="生成时间" width="170"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
      <el-table-column label="操作" width="100"><template #default="{ row }"><el-button link type="primary" @click="openReport(row.id)">下载</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="50" :current-page="page" @current-change="(value: number) => { page = value; load() }" />
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
