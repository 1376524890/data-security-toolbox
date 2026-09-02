<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get } from '../api'
const rows = ref<Array<Record<string, unknown>>>([])
onMounted(async () => { rows.value = await get('/detections') })
</script>
<template>
  <el-card>
    <template #header>统一检测结果</template>
    <el-table :data="rows" stripe>
      <el-table-column prop="engine" label="Engine" />
      <el-table-column prop="rule_id" label="规则" />
      <el-table-column prop="severity" label="严重度" />
      <el-table-column prop="confidence" label="置信度" />
      <el-table-column prop="risk_score" label="风险分" />
      <el-table-column prop="risk_level" label="风险等级" />
      <el-table-column prop="recommendation" label="整改建议" />
    </el-table>
  </el-card>
</template>

