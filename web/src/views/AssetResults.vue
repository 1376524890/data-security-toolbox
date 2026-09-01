<template>
  <div>
    <h2 class="page-title">数据资产识别</h2>
    <div class="toolbar">
      <el-upload
        :auto-upload="false"
        :on-change="onFileChange"
        :limit="1"
        accept=".csv"
      >
        <el-button type="primary">上传 CSV 数据表</el-button>
      </el-upload>
      <el-button v-if="fileObj" type="success" :loading="analyzing" @click="analyze">开始识别</el-button>
    </div>

    <el-alert v-if="engine" :title="engineMsg" type="info" :closable="false" style="margin:14px 0" />

    <div class="panel" v-if="columns.length">
      <div class="panel-title">敏感数据识别结果（按列）</div>
      <el-table :data="columns" stripe>
        <el-table-column prop="column" label="列名" width="200" />
        <el-table-column label="敏感类型">
          <template #default="{ row }">
            <el-tag v-for="t in row.sensitive_types" :key="t" size="small" style="margin-right:6px">{{ t }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="命中占比">
          <template #default="{ row }">
            <span v-for="(v, k) in row.ratio" :key="k" style="margin-right:8px">{{ k }}: {{ (v * 100).toFixed(1) }}%</span>
          </template>
        </el-table-column>
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
const columns = ref([])
const engine = ref('')

const engineMsg = computed(() => '识别引擎：' + engine.value)

function onFileChange(file) {
  fileObj.value = file.raw
  columns.value = []
  engine.value = ''
}

async function analyze() {
  if (!fileObj.value) { ElMessage.warning('请先选择 CSV 文件'); return }
  analyzing.value = true
  const fd = new FormData()
  fd.append('file', fileObj.value)
  try {
    const res = await api.analyzeAsset(fd)
    columns.value = res.data.columns || []
    engine.value = res.data.engine || ''
    if (res.data.fallback) ElMessage.info('未检测到 openDLP，已使用内置正则引擎（fallback）')
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
</style>