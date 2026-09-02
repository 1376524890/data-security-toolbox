<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get } from '../api'
const rows = ref<Array<Record<string, unknown>>>([])
onMounted(async () => { rows.value = await get('/tasks') })
</script>

<template>
  <el-card>
    <template #header>任务系统</template>
    <el-table :data="rows" stripe>
      <el-table-column prop="id" label="ID" />
      <el-table-column prop="kind" label="类型" />
      <el-table-column prop="status" label="状态" />
      <el-table-column prop="progress" label="进度">
        <template #default="{ row }"><el-progress :percentage="Number(row.progress)" /></template>
      </el-table-column>
      <el-table-column prop="current_stage" label="阶段" />
      <el-table-column prop="log" label="日志" />
    </el-table>
  </el-card>
</template>

