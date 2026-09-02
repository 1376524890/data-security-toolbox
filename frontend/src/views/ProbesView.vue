<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { get, post } from '../api'

const rows = ref<Array<Record<string, unknown>>>([])
const form = ref({ name: '', hostname: '', ip_address: '' })
async function refresh() { rows.value = await get('/probes') }
async function register() {
  await post('/probes/register', form.value)
  ElMessage.success('探针已注册')
  await refresh()
}
onMounted(refresh)
</script>

<template>
  <el-card>
    <template #header>探针管理</template>
    <el-form inline>
      <el-form-item label="名称"><el-input v-model="form.name" /></el-form-item>
      <el-form-item label="主机名"><el-input v-model="form.hostname" /></el-form-item>
      <el-form-item label="IP"><el-input v-model="form.ip_address" /></el-form-item>
      <el-button type="primary" @click="register">注册</el-button>
    </el-form>
    <el-table :data="rows" stripe><el-table-column prop="name" label="名称" /><el-table-column prop="hostname" label="主机名" /><el-table-column prop="ip_address" label="IP" /><el-table-column prop="status" label="状态" /></el-table>
  </el-card>
</template>

