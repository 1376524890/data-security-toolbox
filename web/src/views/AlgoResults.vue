<template>
  <div>
    <h2 class="page-title">密码算法评估</h2>
    <div class="toolbar">
      <el-upload :auto-upload="false" :on-change="onFileChange" :limit="1">
        <el-button type="primary">上传代码/配置文件</el-button>
      </el-upload>
      <el-button type="success" :loading="analyzing" @click="analyze">开始评估</el-button>
    </div>

    <div class="panel">
      <div class="panel-title">或粘贴待评估文本</div>
      <el-input v-model="inlineText" type="textarea" :rows="5" placeholder="粘贴含加密算法的代码或配置文本" />
    </div>

    <el-alert v-if="rating" :type="ratingType" :title="`评级：${rating}`" :closable="false" show-icon style="margin:14px 0" />

    <div class="panel" v-if="algorithms.length">
      <div class="panel-title">检测到的算法</div>
      <el-table :data="algorithms" stripe>
        <el-table-column prop="algorithm" label="算法" width="120" />
        <el-table-column prop="name_cn" label="名称" />
        <el-table-column prop="type" label="类型" width="120" />
        <el-table-column label="国密" width="90">
          <template #default="{ row }"><el-tag :type="row.is_sm ? 'success' : 'info'" size="small">{{ row.is_sm ? '是' : '否' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="安全" width="90">
          <template #default="{ row }"><el-tag :type="row.secure ? 'success' : 'danger'" size="small">{{ row.secure ? '安全' : '不安全' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="最小密钥位" width="110">
          <template #default="{ row }">{{ row.min_key_len ?? '—' }}</template>
        </el-table-column>
      </el-table>
    </div>

    <div class="panel" v-if="weaknesses.length">
      <div class="panel-title">弱配置/风险</div>
      <el-table :data="weaknesses" stripe>
        <el-table-column label="风险" width="110">
          <template #default="{ row }"><el-tag :type="riskTag(row.risk)" size="small">{{ row.risk }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="180" />
        <el-table-column prop="desc" label="说明" />
      </el-table>
    </div>

    <div class="panel" v-if="sm.has_sm2 || sm.has_sm3 || sm.has_sm4">
      <div class="panel-title">商用密码（SM）合规</div>
      <el-tag v-if="sm.has_sm2" type="success" style="margin-right:8px">SM2 ✓</el-tag>
      <el-tag v-if="sm.has_sm3" type="success" style="margin-right:8px">SM3 ✓</el-tag>
      <el-tag v-if="sm.has_sm4" type="success">SM4 ✓</el-tag>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const fileObj = ref(null)
const inlineText = ref('')
const analyzing = ref(false)
const rating = ref('')
const algorithms = ref([])
const weaknesses = ref([])
const sm = ref({})

const ratingType = computed(() => ({ '符合（采用国密算法）': 'success',
  '部分符合（需商用密码改造）': 'warning', '不符合（存在高危弱配置）': 'error',
  '不符合（使用不安全算法）': 'error' })[rating.value] || 'info')
const riskTag = (r) => ({ critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[r] || 'info')

function onFileChange(f) {
  fileObj.value = f.raw
  inlineText.value = ''
  reset()
}
function reset() { rating.value = ''; algorithms.value = []; weaknesses.value = []; sm.value = {} }

async function analyze() {
  analyzing.value = true
  const fd = new FormData()
  if (fileObj.value) fd.append('file', fileObj.value)
  else if (inlineText.value) fd.append('inline_text', inlineText.value)
  else { ElMessage.warning('请上传文件或粘贴文本'); analyzing.value = false; return }
  try {
    const res = await api.analyzeAlgo(fd)
    const r = res.data
    rating.value = r.rating?.label || ''
    algorithms.value = r.algorithms_found || []
    weaknesses.value = r.weaknesses || []
    sm.value = r.sm_compliance || {}
  } catch (e) {
    ElMessage.error('评估失败：' + (e.response?.data?.detail || e.message))
  } finally {
    analyzing.value = false
  }
}
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; margin-bottom: 16px; }
.panel-title { font-weight: 700; margin-bottom: 12px; }
</style>