<template>
  <div>
    <h2 class="page-title">任务管理</h2>
    <div class="toolbar">
      <el-form inline>
        <el-form-item label="探针 ID"><el-input v-model="probeId" placeholder="可选，精确过滤" clearable style="width:200px" /></el-form-item>
        <el-form-item label="状态">
          <el-select v-model="status" clearable placeholder="全部" style="width:140px">
            <el-option v-for="s in ['pending','running','done','failed','cancelled']" :key="s" :label="s" :value="s" />
          </el-select>
        </el-form-item>
        <el-form-item><el-button type="primary" @click="load">查询</el-button></el-form-item>
      </el-form>
    </div>
    <div class="panel">
      <el-table :data="tasks" v-loading="loading" stripe>
        <el-table-column prop="task_id" label="任务 ID" width="170" />
        <el-table-column prop="probe_id" label="探针 ID" width="150" />
        <el-table-column prop="collect_type" label="类型" width="120" />
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="200" />
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button v-if="row.status === 'pending'" size="small" type="danger" @click="cancel(row.task_id)">取消</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const probeId = ref('')
const status = ref('')
const tasks = ref([])
const loading = ref(true)

function statusType(s) {
  return { pending: 'warning', running: 'primary', done: 'success', failed: 'danger', cancelled: 'info' }[s] || 'info'
}

async function load() {
  loading.value = true
  try {
    const res = await api.listTasks({ probe_id: probeId.value || undefined, status: status.value || undefined })
    tasks.value = res.data.tasks || []
  } catch (e) { ElMessage.error(e.message) } finally { loading.value = false }
}

async function cancel(id) {
  await api.cancelTask(id)
  ElMessage.success('已取消')
  load()
}

onMounted(load)
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.toolbar { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 14px; margin-bottom: 16px; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; }
</style>