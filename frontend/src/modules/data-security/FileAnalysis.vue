<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'
import { formatBytes, formatDateTime } from '../../utils/format'
import { downloadUrl } from '../../api/client'
import { useFileAnalysis, type FileRecord } from './composables/useFileAnalysis'

// The list, its filters and the detail drawer live in the composable; this
// view only keeps the filter field config, the download helper and the
// row-to-badge wording.
const {
  loading, error, rows, total, detail, drawer, uploading, hiddenInfo, filters,
  load, handleUpload, open, reanalyze, reset,
} = useFileAnalysis()

function downloadOriginal(id: number): void {
  window.open(downloadUrl(`/files/${id}/download`), '_blank')
}

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索文件名', placeholder: '搜索文件名', width: '220px' },
  { key: 'risk_level', label: '风险', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'file_type', label: '类型', type: 'select', options: ['pdf', 'docx', 'jpg', 'png', 'txt', 'zip', 'unknown'].map((v) => ({ label: v, value: v })), width: '120px' },
]

// A file that was never analysed is not "Low"; a document whose parse failed or
// is unsupported is not clean. The backend records the outcome under
// metadata_json.risk, so the list can say so instead of defaulting to Low.
function scanOutcome(row: FileRecord): { kind: 'pending' | 'incomplete' | 'risk'; label: string } {
  const meta = (row.metadata_json || {}) as Record<string, unknown>
  if (!meta || Object.keys(meta).length === 0) return { kind: 'pending', label: '待分析' }
  const status = (meta.risk as { scan_status?: string } | undefined)?.scan_status
  if (status === 'failed') return { kind: 'incomplete', label: '分析失败' }
  if (status === 'unsupported') return { kind: 'incomplete', label: '未支持' }
  return { kind: 'risk', label: row.risk_level }
}
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions>
        <el-upload accept="*/*" :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleUpload(file.raw as File)">
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
        <el-table-column label="风险" width="90"><template #default="{ row }"><el-tag v-if="scanOutcome(row).kind !== 'risk'" type="info" size="small">{{ scanOutcome(row).label }}</el-tag><RiskBadge v-else :level="row.risk_level" /></template></el-table-column>
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
        <div style="margin-top: 12px"><el-button size="small" @click="downloadOriginal(detail.file.id)">下载原文件</el-button></div>

        <div class="sec-title" style="margin-top: 14px">元数据 / EXIF / PDF / DOCX / YARA</div>
        <el-alert v-if="!detail.file.metadata_json.metadata" title="尚无元数据分析结果，请点击分析；可在任务中心查看失败原因。" type="info" :closable="false" />
        <pre v-else class="metadata-content">{{ JSON.stringify(detail.file.metadata_json.metadata, null, 2) }}</pre>
        <div class="sec-title" style="margin-top: 14px">隐写 / 隐藏信息检查</div>
        <template v-if="hiddenInfo">
          <el-alert :title="hiddenInfo.hidden ? '发现隐藏信息线索' : '在已支持的检查范围内未发现隐藏信息'" :type="hiddenInfo.hidden ? 'warning' : 'info'" :closable="false" />
          <div v-for="(finding, index) in hiddenInfo.findings" :key="index" class="hidden-finding">
            <strong>{{ finding.description }}</strong><span v-if="finding.bytes">（{{ finding.bytes }} 字节）</span>
            <pre v-if="finding.preview" class="metadata-content">{{ finding.preview }}</pre>
          </div>
          <p class="scope-note">检查范围：PNG/JPEG 尾部追加数据、DOCX 自定义属性、元数据敏感关键词；不覆盖所有像素隐写或加密载荷。</p>
        </template>
        <el-collapse><el-collapse-item title="完整分析结果 JSON"><JsonViewer :value="detail.file.metadata_json" title="文件元数据 JSON" :height="320" /></el-collapse-item></el-collapse>
        <RawViewer v-if="(detail.file.metadata_json.metadata as any)?.preview" :value="(detail.file.metadata_json.metadata as any).preview" language="plaintext" :height="260" title="原文预览" />

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
.metadata-content { max-height: 360px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 12px; background: var(--soc-bg); color: var(--soc-text); font-size: 12px; }
.hidden-finding { margin-top: 12px; }
.scope-note { font-size: 12px; color: var(--soc-text-dim); }
</style>
