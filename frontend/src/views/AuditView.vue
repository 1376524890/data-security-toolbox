<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get, post } from '../api'

const summary = ref<Record<string, unknown>>({})
const logs = ref('')
const logResult = ref<Record<string, unknown>>({})
async function refresh() { summary.value = await get('/audit/summary') }
async function runLog() { logResult.value = await post('/audit/logs', { content: logs.value }) }
onMounted(refresh)
</script>

<template>
  <el-card>
    <template #header>安全审计</template>
    <pre>{{ summary }}</pre>
    <el-input v-model="logs" type="textarea" :rows="6" placeholder="粘贴日志内容" />
    <el-button style="margin-top: 8px" @click="runLog">分析日志</el-button>
    <pre>{{ logResult }}</pre>
  </el-card>
</template>

