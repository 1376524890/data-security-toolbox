<template>
  <div>
    <h2 class="page-title">网络流量分析</h2>
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
      <el-button v-if="fileObj" type="success" :loading="analyzing" @click="analyze">开始分析</el-button>
    </div>

    <el-alert v-if="engineUsed" :title="`引擎：${engineUsed}，共 ${packetCount} 包`" type="info" :closable="false" style="margin:14px 0" />

    <!-- 告警横幅 -->
    <el-alert v-if="alerts.total_alerts"
              :title="`共 ${alerts.total_alerts} 条告警（${alertSummary}）`"
              type="warning" :closable="false" show-icon style="margin-bottom:16px" />

    <!-- 概览卡片 -->
    <div class="stat-row" v-if="stats.total_sessions !== undefined">
      <div class="stat-card"><div class="label">会话数</div><div class="value">{{ stats.total_sessions }}</div></div>
      <div class="stat-card"><div class="label">总字节</div><div class="value small">{{ fmtBytes(stats.total_bytes) }}</div></div>
      <div class="stat-card"><div class="label">估算速率</div><div class="value small">{{ stats.traffic_rate }} bps</div></div>
      <div class="stat-card"><div class="label">数据包</div><div class="value">{{ stats.packet_count }}</div></div>
    </div>

    <!-- 图表 -->
    <div class="chart-row">
      <div class="panel"><div class="panel-title">协议分布</div><div ref="protoRef" class="chart"></div></div>
      <div class="panel"><div class="panel-title">流量趋势（分桶包数）</div><div ref="trendRef" class="chart"></div></div>
    </div>

    <!-- 会话 TopN -->
    <div class="panel" v-if="stats.top_sessions && stats.top_sessions.length">
      <div class="panel-title">会话 Top 10（按字节）</div>
      <el-table :data="stats.top_sessions" stripe size="small">
        <el-table-column prop="src" label="源" width="220" />
        <el-table-column prop="dst" label="目的" width="220" />
        <el-table-column prop="proto" label="协议" width="90" />
        <el-table-column prop="count" label="包数" width="80" />
        <el-table-column label="字节" width="120">
          <template #default="{ row }"><span class="num">{{ row.bytes ?? 0 }}</span></template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 告警列表 -->
    <div class="panel" v-if="alerts.alerts && alerts.alerts.length">
      <div class="panel-title">入侵检测告警</div>
      <el-table :data="alerts.alerts" stripe size="small" max-height="300">
        <el-table-column prop="time" label="时间" width="200" />
        <el-table-column label="级别" width="90">
          <template #default="{ row }"><el-tag :type="sevType(row.severity)" size="small">{{ row.severity }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="signature" label="告警签名" />
        <el-table-column prop="src_ip" label="源 IP" width="130" />
        <el-table-column prop="dst_ip" label="目的 IP" width="130" />
        <el-table-column prop="proto" label="协议" width="80" />
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import * as echarts from 'echarts'
import { api } from '../api'

const fileObj = ref(null)
const engine = ref('auto')
const analyzing = ref(false)
const engineUsed = ref('')
const packetCount = ref(0)
const stats = ref({})
const alerts = ref({})
const protoRef = ref(null)
const trendRef = ref(null)
let protoChart = null
let trendChart = null

const sevType = (s) => ({ '1': 'danger', '2': 'warning', '3': 'info', high: 'danger',
  medium: 'warning', low: 'info', critical: 'danger', info: 'info' }[String(s)] || 'info')

const alertSummary = computed(() => {
  const sc = alerts.value.severity_count || {}
  const parts = []
  if (sc.critical || sc['1']) parts.push(`危险 ${sc.critical || sc['1']}`)
  if (sc.high || sc['2']) parts.push(`高 ${sc.high || sc['2']}`)
  if (sc.medium || sc['3']) parts.push(`中 ${sc.medium || sc['3']}`)
  if (sc.low) parts.push(`低 ${sc.low}`)
  return parts.join('，') || '（无级别统计）'
})
function fmtBytes(b) {
  b = Number(b || 0)
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

function onFileChange(file) {
  fileObj.value = file.raw
  reset()
}

function reset() {
  engineUsed.value = ''
  packetCount.value = 0
  stats.value = {}
  alerts.value = {}
  protoChart?.clear(); trendChart?.clear()
}

function renderCharts() {
  if (!protoChart) protoChart = echarts.init(protoRef.value)
  if (!trendChart) trendChart = echarts.init(trendRef.value)

  const dist = stats.value.protocol_dist || []
  protoChart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: ['35%', '65%'],
      data: dist.map((d) => ({ name: d.protocol, value: d.count })),
      label: { formatter: '{b}: {c} ({d}%)' }
    }]
  })

  const trend = stats.value.trend || []
  trendChart.setOption({
    tooltip: {},
    xAxis: { type: 'category', data: trend.map((t) => '桶' + t.bucket) },
    yAxis: { type: 'value', name: '包数' },
    series: [{
      type: 'line', smooth: true, areaStyle: {}, data: trend.map((t) => t.count)
    }]
  })
}

async function analyze() {
  if (!fileObj.value) { ElMessage.warning('请先选择 pcap 文件'); return }
  analyzing.value = true
  const fd = new FormData()
  fd.append('file', fileObj.value)
  fd.append('engine', engine.value)
  try {
    const res = await api.analyzeTraffic(fd)
    engineUsed.value = res.data.engine
    packetCount.value = res.data.packet_count
    stats.value = res.data.stats || {}
    alerts.value = res.data.alerts || {}
    await nextTick()
    renderCharts()
  } catch (e) {
    ElMessage.error('分析失败：' + (e.response?.data?.detail || e.message))
  } finally {
    analyzing.value = false
  }
}

function onResize() { protoChart?.resize(); trendChart?.resize() }

onMounted(() => window.addEventListener('resize', onResize))
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  protoChart?.dispose(); trendChart?.dispose(); protoChart = trendChart = null
})
</script>

<style scoped>
.page-title { margin-bottom: 16px; }
.toolbar { display: flex; gap: 12px; align-items: center; }
.stat-row { display: flex; gap: 16px; margin: 16px 0; }
.stat-card { flex: 1; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 16px; }
.label { color: var(--text-secondary); font-size: 13px; }
.value { font-size: 24px; font-weight: 700; margin-top: 4px; }
.value.small { font-size: 14px; font-weight: 600; }
.char { margin-top: 4px; }
.num { font-variant-numeric: tabular-nums; }
.chart-row { display: flex; gap: 16px; margin-bottom: 16px; }
.chart-row .panel { flex: 1; }
.chart { height: 280px; }
.panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 18px; margin-bottom: 16px; }
.panel-title { font-weight: 700; margin-bottom: 12px; }
</style>