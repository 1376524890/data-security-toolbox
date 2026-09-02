<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { downloadUrl, get, post } from '../api'

const rows = ref<Array<Record<string, unknown>>>([])
const title = ref('数据安全检测报告')
async function refresh() { rows.value = await get('/reports') }
async function generate() {
  await post('/reports/generate', { title: title.value, format: 'pdf' })
  ElMessage.success('报告已生成')
  await refresh()
}
function openReport(id: number) {
  window.open(downloadUrl(`/reports/${id}/download`), '_blank')
}
onMounted(refresh)
</script>

<template>
  <el-card>
    <template #header>报告系统</template>
    <el-input v-model="title" style="width: 320px" />
    <el-button type="primary" style="margin-left: 8px" @click="generate">生成报告</el-button>
    <el-table :data="rows" stripe style="margin-top: 16px">
      <el-table-column prop="id" label="ID" />
      <el-table-column prop="title" label="标题" />
      <el-table-column prop="format" label="格式" />
      <el-table-column prop="created_at" label="生成时间" />
      <el-table-column label="下载">
        <template #default="{ row }"><el-button size="small" @click="openReport(row.id)">下载</el-button></template>
      </el-table-column>
    </el-table>
  </el-card>
</template>
