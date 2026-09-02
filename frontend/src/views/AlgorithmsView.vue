<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiPost } from '../api/client'
import JsonViewer from '../components/JsonViewer.vue'

const data = ref('hello world 123456')
const result = ref<Record<string, unknown>>({})
const running = ref(false)

async function run(): Promise<void> {
  running.value = true
  try {
    result.value = await apiPost('/algorithms/randomness', { data: data.value })
    ElMessage.success('评估完成')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    running.value = false
  }
}
</script>

<template>
  <div class="page-card">
    <el-input v-model="data" type="textarea" :rows="5" placeholder="输入待评估数据" />
    <el-button class="run" type="primary" :loading="running" @click="run">运行随机性评估</el-button>
    <JsonViewer :value="result" title="查看评估结果" />
  </div>
</template>

<style scoped>.run { margin: 12px 0; }</style>
