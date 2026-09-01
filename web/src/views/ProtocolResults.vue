<template>
  <div>
    <h2 class="page-title">网络协议分析</h2>
    <div class="toolbar">
      <el-upload :auto-upload="false" :on-change="onFileChange" :limit="1" accept=".pcap,.pcapng,.cap">
        <el-button type="primary">上传 pcap 文件</el-button>
      </el-upload>
      <el-select v-model="engine" style="width:150px" placeholder="解析引擎">
        <el-option value="auto" label="自动(auto)" />
        <el-option value="pyshark" label="pyshark" />
        <el-option value="dpkt" label="dpkt" />
        <el-option value="plain" label="内置回退" />
      </el-select>
      <el-button v-if="fileObj" type="success" :loading="analyzing" @click="analyze">开始解析</el-button>
    </div>

    <el-alert v-if="engineUsed" :title="`解析引擎：${engineUsed}，共 ${packetCount} 个数据包`" type="info" :closable="false" style="margin:14px 0" />

    <div class="panel" v-if="sessions.length">
      <div class="panel-title">会话列表（五元组重组）</div>
      <el-table :data="sessions" stripe max-height="260">
        <el-table-column prop="src" label="源" />
        <el-table-column prop="dst" label="目的" />
        <el-table-column prop="proto" label="协议" width="90" />
        <el-table-column prop="count" label="包数" width="80" />
        <el-table-column label="字节数" width="120">
          <template #default="{ row }">{{ row.bytes ?? 0 }}</template>
        </el-table-column>
      </el-table>
    </div>

    <div class="panel" v-if="packets.length">
      <div class="panel-title">数据包列表（前 {{ packets.length }} 条）</div>
      <el-table :data="packets" stripe max-height="360" size="small">
        <el-table-column prop="index" label="# " width="60" />
        <el-table-column label="源" width="200">
          <template #default="{ row }">{{ row.src || (row.connection?.src || '—') }}</template>
        </el-table-column>
        <el-table-column label="目的" width="200">
          <template #default="{ row }">{{ row.dst || (row.connection?.dst || '—') }}</template>
        </el-table-column>
        <el-table-column label="协议/层">
          <template #default="{ row }">
            <el-tag v-for="l in row.layers" :key="l" size="small" style="margin-right:4px">{{ l }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const fileObj = ref(null)
const engine = ref('auto')
const analyzing = ref(false)
const engineUsed = ref('')
const packetCount = ref(0)
const sessions = ref([])
const packets = ref([])

function onFileChange(file) {
  fileObj.value = file.raw
  sessions.value = []
  packets.value = []
  engineUsed.value = ''
}

async function analyze() {
  if (!fileObj.value) { ElMessage.warning('请先选择 pcap 文件'); return }
  analyzing.value = true
  const fd = new FormData()
  fd.append('file', fileObj.value)
  fd.append('engine', engine.value)
  try {
    const res = await api.analyzeProtocol(fd)
    engineUsed.value = res.data.engine
    packetCount.value = res.data.packet_count
    sessions.value = res.data.sessions || []
    packets.value = res.data.packets || []
  } catch (e) {
    ElMessage.error('解析失败：' + (e.response?.data?.detail || e.message))
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