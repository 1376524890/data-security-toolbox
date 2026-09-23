<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import StateBox from '../../../components/common/StateBox.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { apiGet } from '../../../api/client'
import { formatCoverage, formatTerminationReason } from '../../../utils/format'

// The risky files a scan actually produced. This reads the data-object model
// (asset instances with at least one value-level detection) rather than the
// upload table, so a scan that collected files shows its evidence here instead
// of an empty page.
interface RiskFile {
  id: number; name: string; path: string; source_kind: string; source_name: string
  host: string; level: string; sensitivity: string; categories: string[]
  size: number; coverage: string; termination_reason: string; status: string
  last_seen_at: string; permission: string
}

const loading = ref(true)
const error = ref('')
const rows = ref<RiskFile[]>([])
const total = ref(0)
const filters = reactive({ page: 1, page_size: 50, search: '', level: '', source_kind: '' })
const selected = ref<RiskFile | null>(null)
const drawer = ref(false)
// The preview re-reads the file from its source on demand; the platform keeps no
// file body, so the button is the only way to see the original content.
const preview = ref<{ loading: boolean; error: string; text: string; hex: string; encoding: string; truncated: boolean; size: number }>(
  { loading: false, error: '', text: '', hex: '', encoding: '', truncated: false, size: 0 })

const LEVELS = ['L4', 'L3', 'L2', 'L1']
const SOURCES = [{ l: '主机文件', v: 'file' }, { l: '共享文件', v: 'file_share' }, { l: '数据库', v: 'database' }]

const levelRows = computed(() => rows.value)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const page = await apiGet<{ items: RiskFile[]; total: number }>('/asset-instances', {
      sensitive_only: true, page: filters.page, page_size: filters.page_size,
      search: filters.search || undefined, source_kind: filters.source_kind || undefined,
    })
    rows.value = page.items
    total.value = page.total
  } catch (err) {
    error.value = String(err)
  } finally {
    loading.value = false
  }
}

function open(row: RiskFile): void {
  selected.value = row
  drawer.value = true
  preview.value = { loading: false, error: '', text: '', hex: '', encoding: '', truncated: false, size: 0 }
}

async function loadPreview(): Promise<void> {
  if (!selected.value) return
  preview.value = { ...preview.value, loading: true, error: '' }
  try {
    const data = await apiGet<{ text: string | null; hex: string | null; encoding: string; truncated: boolean; size: number }>(
      `/asset-instances/${selected.value.id}/content`)
    preview.value = { loading: false, error: '', text: data.text || '', hex: data.hex || '',
      encoding: data.encoding, truncated: data.truncated, size: data.size }
  } catch (err) {
    preview.value = { ...preview.value, loading: false, error: String(err) }
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <strong>风险文件</strong>
      <span class="muted">已扫描到敏感内容的文件（值命中，按分级排序）</span>
      <div class="toolbar-spacer" />
      <el-input v-model="filters.search" clearable placeholder="路径 / 文件名" style="width: 220px"
                @keyup.enter="load()" @clear="load()" />
      <el-select v-model="filters.source_kind" clearable placeholder="全部来源" style="width: 140px" @change="load()">
        <el-option v-for="item in SOURCES" :key="item.v" :label="item.l" :value="item.v" />
      </el-select>
      <el-button @click="load">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="!rows.length"
              empty-text="还没有扫到含敏感内容的文件；先在任务中心下发一次扫描" @retry="load">
      <el-table :data="levelRows" size="small" @row-click="open">
        <el-table-column label="文件" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            <strong>{{ row.name }}</strong>
            <div class="muted">{{ row.path }}</div>
          </template>
        </el-table-column>
        <el-table-column label="来源" min-width="170">
          <template #default="{ row }">
            {{ row.source_name || row.owner_key || row.source_kind }}
            <div class="muted">{{ row.host }}</div>
          </template>
        </el-table-column>
        <el-table-column label="分级" width="150">
          <template #default="{ row }">
            <el-tag size="small" :type="row.level === 'L4' ? 'danger' : row.level === 'L3' ? 'warning' : 'info'">
              {{ row.level }} {{ row.sensitivity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="命中类别" min-width="180">
          <template #default="{ row }">
            <el-tag v-for="category in row.categories" :key="category" size="small" style="margin: 2px">{{ category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="size" label="字节" width="100" />
        <el-table-column label="覆盖 / 状态" width="180">
          <template #default="{ row }">
            {{ row.status }}
            <div class="muted">{{ formatCoverage(row.coverage) }} · {{ formatTerminationReason(row.termination_reason) }}</div>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination background layout="total, prev, pager, next" :total="total"
                     :page-size="filters.page_size" :current-page="filters.page"
                     style="margin-top: 10px"
                     @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <el-drawer v-model="drawer" title="风险文件详情" size="60%">
      <template v-if="selected">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="路径"><span class="wrap">{{ selected.path }}</span></el-descriptions-item>
          <el-descriptions-item label="来源">{{ selected.source_name }} · {{ selected.host }}（{{ selected.source_kind }}）</el-descriptions-item>
          <el-descriptions-item label="分级">{{ selected.level }} · {{ selected.sensitivity }}</el-descriptions-item>
          <el-descriptions-item label="命中类别">{{ selected.categories.join(', ') || '—' }}</el-descriptions-item>
          <el-descriptions-item label="覆盖口径">{{ formatCoverage(selected.coverage) }} / {{ formatTerminationReason(selected.termination_reason) }}</el-descriptions-item>
          <el-descriptions-item label="权限">{{ selected.permission || '未上报' }}</el-descriptions-item>
        </el-descriptions>
        <div class="section-title">原文件预览
          <el-button size="small" type="primary" style="margin-left: 10px"
                     :loading="preview.loading" @click="loadPreview">读取原文件</el-button>
        </div>
        <div v-if="preview.error" class="preview-error">{{ preview.error }}</div>
        <template v-else-if="preview.text || preview.hex">
          <div class="muted">
            编码 {{ preview.encoding }} · 预览 {{ preview.text ? preview.text.length : preview.hex.length / 2 }} 字节
            <span v-if="preview.truncated">（文件共 {{ preview.size }} 字节，仅显示前 64 KiB）</span>
          </div>
          <pre v-if="preview.text" class="preview">{{ preview.text }}</pre>
          <pre v-else class="preview">{{ preview.hex }}</pre>
        </template>
        <div v-else class="muted">点击「读取原文件」从采集来源只读回取该文件（最多 64 KiB，平台不留存文件本体）。</div>

        <div class="section-title">原始记录</div>
        <JsonViewer :value="selected" />
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.muted { color: var(--soc-text-dim); font-size: 12px; }
.section-title { font-weight: 600; margin: 14px 0 8px; }
.wrap { overflow-wrap: anywhere; }
.preview { background: var(--soc-panel-2); border: 1px solid var(--soc-border); border-radius: 6px;
           padding: 10px; font-size: 12px; max-height: 320px; overflow: auto; white-space: pre-wrap; }
.preview-error { color: var(--soc-warning); font-size: 12px; }
:deep(.el-table__row) { cursor: pointer; }
</style>
