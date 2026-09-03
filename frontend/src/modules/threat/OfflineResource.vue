<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listOfflineResources, uploadOffline } from '../../api/offline'
import type { OfflineResource } from '../../types/offline'
import StateBox from '../../components/common/StateBox.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import { formatDateTime } from '../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<OfflineResource[]>([])
const resourceType = ref('ioc')
const uploading = ref(false)

const resourceTypes = [
  { label: 'IOC', value: 'ioc' },
  { label: 'CVE', value: 'cve' },
  { label: 'Suricata Rules', value: 'suricata_rules' },
  { label: 'Sigma Rules', value: 'sigma_rules' },
  { label: 'Model', value: 'model' },
]

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

async function handleUpload(file: File): Promise<void> {
  uploading.value = true
  try {
    const result = await uploadOffline(file, resourceType.value)
    ElMessage.success(`导入 ${result.imported} 条，跳过 ${result.duplicates} 条重复`)
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
  <div>
    <div class="toolbar">
      <el-select v-model="resourceType" style="width: 160px">
        <el-option v-for="t in resourceTypes" :key="t.value" :label="t.label" :value="t.value" />
      </el-select>
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleUpload(file.raw as File)">
        <el-button :loading="uploading" type="primary">导入离线资源</el-button>
      </el-upload>
      <div class="toolbar-spacer" />
      <el-button @click="load">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small">
        <el-table-column prop="resource_type" label="类型" width="150" />
        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="version" label="版本" width="100" />
        <el-table-column prop="count" label="数量" width="80" />
        <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        <el-table-column label="导入时间" width="160"><template #default="{ row }">{{ formatDateTime(row.imported_at) }}</template></el-table-column>
        <el-table-column label="元数据" width="90"><template #default="{ row }"><JsonViewer :value="row.resource_metadata" title="查看" :height="160" /></template></el-table-column>
      </el-table>
    </StateBox>
  </div>
</template>
