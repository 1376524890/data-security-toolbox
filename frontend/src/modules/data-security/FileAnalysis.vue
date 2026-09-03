<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost, apiUpload } from '../../api/client'
import type { PageResult } from '../../types/common'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'
import { formatBytes, formatDateTime } from '../../utils/format'

interface FileRecord { id: number; name: string; path: string; size: number; sha256: string; file_type: string; metadata_json: Record<string, unknown>; risk_level: string; created_at: string }
interface FileDetail { file: FileRecord; findings: Array<Record<string, unknown>>; data_assets: Array<Record<string, unknown>> }

const loading = ref(true)
const error = ref('')
const rows = ref<FileRecord[]>([])
const total = ref(0)
const detail = ref<FileDetail | null>(null)
const drawer = ref(false)
const uploading = ref(false)
const filters = reactive({ search: '', file_type: '', risk_level: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索文件名', placeholder: '搜索文件名', width: '220px' },
  { key: 'risk_level', label: '风险', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'file_type', label: '类型', type: 'select', options: ['pdf', 'docx', 'jpg', 'png', 'txt', 'zip', 'unknown'].map((v) => ({ label: v, value: v })), width: '120px' },
]

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await apiGet<PageResult<FileRecord>>('/files', { ...filters })
    rows.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function handleUpload(file: File): Promise<void> {
  uploading.value = true
  try {
    await apiUpload('/files/upload', file)
    ElMessage.success('文件已上传')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    uploading.value = false
  }
}

async function open(row: FileRecord): Promise<void> {
  try {
    detail.value = await apiGet<FileDetail>(`/files/${row.id}`)
    drawer.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function reanalyze(row: FileRecord): Promise<void> {
  try {
    await apiPost(`/files/${row.id}/analyze`)
    ElMessage.success('已触发重新分析')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions>
        <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleUpload(file.raw as File)">
          <el-button :loading="uploading" type="primary">上传文件</el-button>
        </el-upload>
      </template>
    </FilterBar>
    <StateBox :loading="loading" :error="error" :empty="!rows.length" @retry="load">
      <el-table :data="rows" size="small" @row-click="open">
        <el-table-column prop="name" label="文件名" min-width="200" show-overflow-tooltip />
        <el-table-column prop="file_type" label="类型" width="100" />
        <el-table-column label="大小" width="90"><template #default="{ row }">{{ formatBytes(row.size) }}</template></el-table-column>
        <el-table-column prop="sha256" label="SHA256" min-width="220" show-overflow-tooltip />
        <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :level="row.risk_level" /></template></el-table-column>
        <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="130"><template #default="{ row }"><el-button size="small" @click.stop="reanalyze(row)">分析</el-button><el-button size="small" type="primary" @click.stop="open(row)">详情</el-button></template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="文件分析详情" width="62%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="文件名">{{ detail.file.name }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ detail.file.file_type }}</el-descriptions-item>
          <el-descriptions-item label="大小">{{ formatBytes(detail.file.size) }}</el-descriptions-item>
          <el-descriptions-item label="风险"><RiskBadge :level="detail.file.risk_level" /></el-descriptions-item>
          <el-descriptions-item label="SHA256" :span="2"><span class="mono">{{ detail.file.sha256 }}</span></el-descriptions-item>
        </el-descriptions>

        <div class="sec-title" style="margin-top: 14px">元数据 / EXIF / PDF / DOCX / YARA</div>
        <JsonViewer :value="detail.file.metadata_json" title="文件元数据 JSON" :height="320" />

        <div class="sec-title" style="margin-top: 14px">关联检测</div>
        <el-table :data="detail.findings" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="engine" label="引擎" width="120" />
          <el-table-column prop="rule_id" label="规则" min-width="140" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
        </el-table>

        <div class="sec-title" style="margin-top: 14px">关联数据资产</div>
        <el-table :data="detail.data_assets" size="small">
          <el-table-column prop="name" label="名称" min-width="160" />
          <el-table-column prop="asset_type" label="类型" width="120" />
        </el-table>
      </template>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
