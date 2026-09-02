<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { get } from '../api'

const rows = ref<Array<Record<string, unknown>>>([])
onMounted(async () => { rows.value = await get('/assets') })
</script>

<template>
  <el-card>
    <template #header>数据资产识别</template>
    <el-table :data="rows" stripe>
      <el-table-column prop="ip" label="IP" />
      <el-table-column prop="hostname" label="主机名" />
      <el-table-column prop="service" label="服务" />
      <el-table-column prop="port" label="端口" />
      <el-table-column prop="asset_type" label="资产类型" />
      <el-table-column prop="risk_level" label="风险等级" />
      <el-table-column prop="sensitive_categories" label="敏感数据">
        <template #default="{ row }">{{ (row.sensitive_categories as string[]).join(', ') }}</template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

