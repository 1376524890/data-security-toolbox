<template>
  <div>
    <h2 class="page-title">正则生成器（openDLP）</h2>
    <el-alert title="上传正例 / 负例样本 CSV，基于样本自动学习生成正则表达式" type="info" :closable="false" style="margin-bottom:16px" />
    <div class="panel">
      <div class="flex">
        <div class="upload-box">
          <div class="box-label">正例样本（必须）</div>
          <el-upload drag :auto-upload="false" :limit="1" :on-change="(f) => (posFile = f.raw)" accept=".csv">
            <el-icon style="font-size:32px;color:var(--color-primary)"><component is="UploadFilled" /></el-icon>
            <div class="el-upload__text">拖拽或点击上传正例 CSV</div>
          </el-upload>
        </div>
        <div class="upload-box">
          <div class="box-label">负例样本（可选）</div>
          <el-upload drag :auto-upload="false" :limit="1" :on-change="(f) => (negFile = f.raw)" accept=".csv">
            <el-icon style="font-size:32px;color:var(--color-primary)"><component is="UploadFilled" /></el-icon>
            <div class="el-upload__text">拖拽或点击上传负例 CSV</div>
          </el-upload>
        </div>
      </div>
      <el-button type="primary" :loading="running" @click="generateRegen" style="margin-top:16px">生成正则表达式</el-button>
    </div>

    <div class="panel" v-if="regexes.length">
      <div class="panel-title">生成结果（引擎：{{ engine }}；正例 {{ posCount }} / 负例 {{ negCount }}）</div>
      <div v-for="(r, i) in regexes" :key="i" class="regex-item">
        <code>{{ r.pattern }}</code>
        <el-button size="small" @click="copyRegex(r.pattern)">复制</el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const posFile = ref(null)
const negFile = ref(null)
const running = ref(false)
const regexes = ref([])
const engine = ref('')
const posCount = ref(0)
const negCount = ref(0)

async function generateRegen() {
  if (!posFile.value) { ElMessage.warning('请上传正例样本'); return }
  running.value = true
  const fd = new FormData()
  fd.append('positive', posFile.value)
  if (negFile.value) fd.append('negative', negFile.value)
  try {
    const res = await api.regexGen(fd)
    regexes.value = res.data.regexes || []
    engine.value = res.data.engine || ''
    posCount.value = res.data.positive_count || 0
    negCount.value = res.data.negative_count || 0
  } catch (e) {
    ElMessage.error('生成失败：' + (e.response?.data?.detail || e.message))
  } finally {
    running.value = false
  }
}

function copyRegex(p) {
  navigator.clipboard?.writeText(p)
  ElMessage.success('已复制')
}
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; margin-bottom: 16px; }
.panel-title { font-weight: 700; margin-bottom: 12px; }
.flex { display: flex; gap: 20px; }
.upload-box { flex: 1; }
.box-label { margin-bottom: 8px; font-size: 13px; color: var(--text-secondary); }
.regex-item { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px dashed var(--border-color); }
.regex-item code { background: var(--bg-code); padding: 4px 8px; border-radius: var(--radius-sm); flex: 1; word-break: break-all; color: var(--text-primary); }
</style>