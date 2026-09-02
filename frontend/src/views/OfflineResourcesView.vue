<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import StatusBadge from '../components/StatusBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listOfflineResources, uploadOffline } from '../api/offline'
import type { OfflineResource } from '../types/offline'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<OfflineResource[]>([])
const resourceType = ref('ioc')
const name = ref('')
const version = ref('1.0.0')
const uploading = ref(false)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = await listOfflineResources()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function handleFile(file: File): Promise<void> {
  uploading.value = true
  try {
    const result = await uploadOffline(file, resourceType.value, name.value, version.value)
    if (result.errors.length) ElMessage.warning(result.errors.join('; '))
    else ElMessage.success(`导入 ${result.imported} 条`)
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    uploading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-select v-model="resourceType"><el-option label="IOC" value="ioc" /><el-option label="CVE" value="cve" /><el-option label="Suricata Rules" value="suricata_rules" /><el-option label="Sigma Rules" value="sigma_rules" /><el-option label="Presidio Models" value="model" /></el-select>
      <el-input v-model="name" placeholder="资源名称" />
      <el-input v-model="version" placeholder="版本" />
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleFile(file.raw as File)"><el-button type="primary" :loading="uploading">上传离线 Bundle</el-button></el-upload>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column prop="resource_type" label="类型" />
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="version" label="版本" />
      <el-table-column prop="count" label="数量" />
      <el-table-column label="导入时间" width="170"><template #default="{ row }">{{ formatDateTime(row.imported_at) }}</template></el-table-column>
      <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
      <el-table-column prop="storage_path" label="存储路径" />
    </el-table>
  </div>
</template>
