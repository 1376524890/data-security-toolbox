<template>
  <div>
    <h2 class="page-title">探针管理</h2>
    <div class="panel">
      <el-table :data="probes" v-loading="loading" stripe>
        <el-table-column prop="probe_id" label="探针 ID" width="150" />
        <el-table-column prop="hostname" label="主机名" />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'info'">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="CPU %" width="90">
          <template #default="{ row }">{{ (row.cpu_usage ?? 0).toFixed(1) }}</template>
        </el-table-column>
        <el-table-column label="内存 MB" width="100">
          <template #default="{ row }">{{ (row.memory_usage_mb ?? 0).toFixed(1) }}</template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最后上报" width="200" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'

const probes = ref([])
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await api.probes()
    probes.value = res.data.probes || []
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; }
</style>