<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get } from '../api'
const summary = ref<Record<string, unknown>>({})
const engines = ref<Array<Record<string, unknown>>>([])
onMounted(async () => {
  summary.value = await get('/risk/summary')
  engines.value = await get('/engine/registry')
})
</script>
<template>
  <el-card>
    <template #header>统一风险评分</template>
    <pre>{{ summary }}</pre>
    <h3>检测引擎</h3>
    <el-table :data="engines" stripe><el-table-column prop="name" label="名称" /><el-table-column prop="version" label="版本" /></el-table>
  </el-card>
</template>

