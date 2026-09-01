<template>
  <div>
    <h2 class="page-title">元数据分析</h2>
    <div class="toolbar">
      <el-upload :auto-upload="false" :on-change="onFileChange" :limit="1">
        <el-button type="primary">上传文件（图片/PDF/Office）</el-button>
      </el-upload>
      <el-button v-if="fileObj" type="success" :loading="analyzing" @click="analyze">开始分析</el-button>
    </div>

    <el-alert v-if="risk" :type="riskType" :title="`风险等级：${riskLabel}`" :closable="false" show-icon style="margin:14px 0" />

    <div class="panel" v-if="meta.file">
      <div class="panel-title">文件信息</div>
      <el-descriptions :column="3" border size="small">
        <el-descriptions-item label="文件名">{{ meta.file.name }}</el-descriptions-item>
        <el-descriptions-item label="类型">{{ meta.file.detected_type }}</el-descriptions-item>
        <el-descriptions-item label="大小">{{ fmtSize(meta.file.size_bytes) }}</el-descriptions-item>
        <el-descriptions-item label="扩展名">{{ meta.file.extension || '—' }}</el-descriptions-item>
        <el-descriptions-item label="ExifTool">{{ meta.exiftool_used ? '启用' : '内置解析' }}</el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="panel" v-if="hasMetadata">
      <div class="panel-title">提取的元数据</div>
      <pre class="meta-pre">{{ metadataJson }}</pre>
    </div>

    <div class="panel" v-if="findings.length">
      <div class="panel-title">敏感元数据发现</div>
      <el-table :data="findings" stripe>
        <el-table-column prop="field" label="字段" width="180" />
        <el-table-column label="风险" width="100">
          <template #default="{ row }"><el-tag :type="riskTag(row.risk)" size="small">{{ row.risk }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="desc" label="说明" />
        <el-table-column prop="value" label="值" show-overflow-tooltip />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const fileObj = ref(null)
const analyzing = ref(false)
const meta = ref({})
const findings = ref([])
const risk = ref('')

const riskLabel = computed(() => ({ high: '高', medium: '中', low: '低', none: '无', unknown: '未知' })[risk.value] || '')
const riskType = computed(() => ({ high: 'error', medium: 'warning', low: 'info', none: 'success', unknown: 'info' })[risk.value] || 'info')
const riskTag = (r) => ({ high: 'danger', medium: 'warning', low: 'info' }[r] || 'info')

const hasMetadata = computed(() => Object.keys(meta.value.metadata || {}).length > 0)
const metadataJson = computed(() => JSON.stringify(meta.value.metadata || {}, null, 2))

function fmtSize(b) {
  b = Number(b || 0)
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

function onFileChange(f) { fileObj.value = f.raw; reset() }
function reset() { meta.value = {}; findings.value = []; risk.value = '' }

async function analyze() {
  if (!fileObj.value) { ElMessage.warning('请先选择文件'); return }
  analyzing.value = true
  const fd = new FormData()
  fd.append('file', fileObj.value)
  try {
    const res = await api.analyzeMetadata(fd)
    meta.value = res.data
    findings.value = res.data.sensitive_findings || []
    risk.value = res.data.risk_level || ''
  } catch (e) {
    ElMessage.error('分析失败：' + (e.response?.data?.detail || e.message))
  } finally {
    analyzing.value = false
  }
}
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.toolbar { display: flex; gap: 12px; align-items: center; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; margin-top: 16px; }
.panel-title { font-weight: 700; margin-bottom: 12px; }
.meta-pre { background: var(--bg-code); padding: 12px; border-radius: var(--radius-sm); max-height: 320px; overflow: auto; font-size: 12px; color: var(--text-primary); }
</style>