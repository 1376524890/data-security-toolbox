<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { apiGet, apiPost } from '../api/client'
import JsonViewer from '../components/JsonViewer.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'

interface AuditSummary { assets: number; files: number; pcaps: number; anomalies: number; [key: string]: unknown }
interface LogResult { line_count: number; matches: Record<string, string[]>; [key: string]: unknown }

const loading = ref(true)
const error = ref('')
const summary = ref<AuditSummary>({ assets: 0, files: 0, pcaps: 0, anomalies: 0 })
const logs = ref('')
const logResult = ref<LogResult>({ line_count: 0, matches: {} })

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    summary.value = await apiGet('/audit/summary')
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function runLog(): Promise<void> {
  try {
    logResult.value = await apiPost<LogResult>('/audit/logs', { content: logs.value })
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

onMounted(refresh)
</script>

<template>
  <div class="page-card">
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="refresh" />
    <template v-else>
      <el-descriptions :column="4" border><el-descriptions-item label="资产">{{ summary.assets }}</el-descriptions-item><el-descriptions-item label="文件">{{ summary.files }}</el-descriptions-item><el-descriptions-item label="PCAP">{{ summary.pcaps }}</el-descriptions-item><el-descriptions-item label="异常">{{ summary.anomalies }}</el-descriptions-item></el-descriptions>
      <JsonViewer :value="summary" title="查看审计摘要" />
      <el-divider content-position="left">日志分析</el-divider>
      <el-input v-model="logs" type="textarea" :rows="6" placeholder="粘贴日志内容" />
      <el-button class="run" type="primary" @click="runLog">分析日志</el-button>
      <JsonViewer :value="logResult" title="查看日志分析结果" />
    </template>
  </div>
</template>

<style scoped>.run { margin: 10px 0; }</style>
