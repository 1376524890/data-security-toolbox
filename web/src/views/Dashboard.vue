<template>
  <div>
    <h2 class="page-title">总览仪表盘</h2>
    <div class="stat-row">
      <div class="stat-card"><div class="label">在线探针</div><div class="value ok">{{ stats.online_probes || '0 / 0' }}</div></div>
      <div class="stat-card"><div class="label">运行中任务</div><div class="value">{{ stats.running_tasks ?? 0 }}</div></div>
      <div class="stat-card"><div class="label">最近上报</div><div class="value small">{{ stats.recent_upload || '—' }}</div></div>
    </div>

    <div class="panel">
      <div class="panel-title">探针状态</div>
      <el-table :data="stats.probes || []" v-loading="loading" stripe>
        <el-table-column prop="probe_id" label="探针 ID" width="140" />
        <el-table-column prop="hostname" label="主机名" />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'info'">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最后上报" width="200" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'

const stats = ref({})
const loading = ref(true)

onMounted(async () => {
  try {
    const res = await api.dashboard()
    stats.value = res.data
  } catch (e) {
    console.error(e)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.stat-row { display: flex; gap: 16px; margin-bottom: 20px; }
.stat-card { flex: 1; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; }
.label { color: var(--text-secondary); font-size: 13px; }
.value { font-size: 28px; font-weight: 700; margin-top: 6px; }
.value.ok { color: var(--color-success); }
.value.small { font-size: 14px; font-weight: 500; color: var(--text-secondary); }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; }
.panel-title { font-weight: 700; margin-bottom: 12px; }
</style>