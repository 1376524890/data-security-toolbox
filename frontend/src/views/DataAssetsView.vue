<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get } from '../api'
const rows = ref<Array<Record<string, unknown>>>([])
onMounted(async () => { rows.value = await get('/data/assets') })
</script>
<template>
  <el-card>
    <template #header>数据资产地图</template>
    <el-table :data="rows" stripe>
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="asset_type" label="类型" />
      <el-table-column prop="sensitivity" label="敏感度" />
      <el-table-column prop="source" label="来源" />
      <el-table-column prop="columns" label="字段">
        <template #default="{ row }">{{ (row.columns as Array<any>).map((c: any) => `${c.name}:${c.sensitivity}`).join(', ') }}</template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

