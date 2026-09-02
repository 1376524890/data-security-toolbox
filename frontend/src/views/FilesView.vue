<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import JsonViewer from '../components/JsonViewer.vue'
import { apiGet, apiUpload } from '../api/client'
import { formatBytes, formatDateTime } from '../utils/format'

interface FileRecord { id: number; name: string; file_type: string; size: number; sha256: string; risk_level: string; metadata_json?: Record<string, unknown>; created_at: string }

const loading = ref(true)
const error = ref('')
const rows = ref<FileRecord[]>([])
const total = ref(0)
const page = ref(1)
const uploading = ref(false)
const detail = ref<FileRecord | null>(null)
const drawer = ref(false)

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await apiGet<{ items: FileRecord[]; total: number }>('/files', { page: page.value, page_size: 50 })
    rows.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function handleFile(file: File): Promise<void> {
  uploading.value = true
  try {
    await apiUpload('/files/upload', file)
    ElMessage.success('上传成功')
    refresh()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    uploading.value = false
  }
}

async function open(row: FileRecord): Promise<void> {
  try {
    detail.value = await apiGet<FileRecord>(`/files/${row.id}`)
    drawer.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

onMounted(refresh)
</script>

<template>
  <div class="page-card">
    <div class="toolbar"><el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleFile(file.raw as File)"><el-button :loading="uploading">上传 JPG/PNG/PDF/DOCX</el-button></el-upload></div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="refresh" />
    <EmptyState v-else-if="!rows.length" />
    <el-table v-else :data="rows" stripe>
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="file_type" label="类型" />
      <el-table-column label="大小" width="100"><template #default="{ row }">{{ formatBytes(row.size) }}</template></el-table-column>
      <el-table-column prop="sha256" label="SHA256" />
      <el-table-column label="风险" width="90"><template #default="{ row }"><SeverityBadge :value="row.risk_level" /></template></el-table-column>
      <el-table-column label="时间" width="170"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
      <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="open(row)">详情</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="50" :current-page="page" @current-change="(value: number) => { page = value; refresh() }" />
    <el-drawer v-model="drawer" title="文件详情" size="48%"><template v-if="detail"><el-descriptions :column="2" border><el-descriptions-item label="名称">{{ detail.name }}</el-descriptions-item><el-descriptions-item label="类型">{{ detail.file_type }}</el-descriptions-item><el-descriptions-item label="SHA256">{{ detail.sha256 }}</el-descriptions-item><el-descriptions-item label="风险">{{ detail.risk_level }}</el-descriptions-item></el-descriptions><JsonViewer :value="detail.metadata_json" title="查看元数据" /></template></el-drawer>
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
