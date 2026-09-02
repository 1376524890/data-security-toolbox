<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import JsonViewer from '../components/JsonViewer.vue'
import { listPcaps, getPcap, analyzePcap, uploadPcap, getPcapFlows, getPcapPackets, getPcapAlerts, getPcapDns, getPcapHttp, getPcapTls, getPcapFiles, getTraffic } from '../api/pcaps'
import type { PcapRecord, Flow, Packet, AlertItem, TrafficOverview } from '../types/pcap'
import { formatBytes, formatDateTime, formatDuration } from '../utils/format'
import { useEcharts } from '../composables/useEcharts'

const loading = ref(true)
const error = ref('')
const items = ref<PcapRecord[]>([])
const total = ref(0)
const selected = ref<PcapRecord | null>(null)
const drawer = ref(false)
const active = ref('overview')
const flows = ref<Flow[]>([])
const packets = ref<Packet[]>([])
const alerts = ref<AlertItem[]>([])
const dns = ref<Array<Record<string, unknown>>>([])
const http = ref<Array<Record<string, unknown>>>([])
const tls = ref<Array<Record<string, unknown>>>([])
const files = ref<Array<Record<string, unknown>>>([])
const traffic = ref<TrafficOverview | null>(null)
const trafficEl = ref<HTMLElement | null>(null)
const trafficChart = useEcharts(trafficEl)
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listPcaps({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function handleFile(file: File): Promise<void> {
  try {
    await uploadPcap(file)
    ElMessage.success('PCAP 已上传')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function runAnalyze(row: PcapRecord): Promise<void> {
  try {
    await analyzePcap(row.id)
    ElMessage.success('已触发分析')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function open(row: PcapRecord): Promise<void> {
  try {
    selected.value = await getPcap(row.id)
    active.value = 'overview'
    drawer.value = true
    await Promise.all([
      getPcapFlows(row.id).then((value) => { flows.value = value.items }),
      getPcapPackets(row.id).then((value) => { packets.value = value.items }),
      getPcapAlerts(row.id).then((value) => { alerts.value = value.items }),
      getPcapDns(row.id).then((value) => { dns.value = value.items }),
      getPcapHttp(row.id).then((value) => { http.value = value.items }),
      getPcapTls(row.id).then((value) => { tls.value = value.items }),
      getPcapFiles(row.id).then((value) => { files.value = value.items }),
      getTraffic(row.id).then((value) => {
        traffic.value = value
        trafficChart.setOption({
          tooltip: { trigger: 'axis' },
          xAxis: { type: 'category', data: value.trend.map((item) => item.time) },
          yAxis: { type: 'value' },
          series: [
            { name: 'Packets', type: 'line', smooth: true, data: value.trend.map((item) => item.packets) },
            { name: 'Bytes', type: 'line', smooth: true, data: value.trend.map((item) => item.bytes) },
          ],
        })
      }),
    ])
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }
onMounted(load)
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleFile(file.raw as File)"><el-button>上传 PCAP/PCAPNG</el-button></el-upload>
      <el-input v-model="filters.search" placeholder="搜索文件名" clearable @keyup.enter="reset" />
      <el-select v-model="filters.status" placeholder="状态" clearable><el-option v-for="item in ['pending', 'analyzed', 'failed']" :key="item" :label="item" :value="item" /></el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column prop="filename" label="文件" />
      <el-table-column label="大小" width="100"><template #default="{ row }">{{ formatBytes(row.size) }}</template></el-table-column>
      <el-table-column prop="packet_count" label="包数" width="90" />
      <el-table-column label="时长" width="90"><template #default="{ row }">{{ formatDuration(row.duration) }}</template></el-table-column>
      <el-table-column label="捕获时间" width="160"><template #default="{ row }">{{ formatDateTime(row.capture_start) }}</template></el-table-column>
      <el-table-column prop="status" label="状态" width="100" />
      <el-table-column label="操作" width="150"><template #default="{ row }"><el-button size="small" @click="runAnalyze(row)">分析</el-button><el-button size="small" type="primary" @click="open(row)">详情</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="PCAP Workbench" size="75%">
      <template v-if="selected">
        <el-descriptions :column="4" border><el-descriptions-item label="文件">{{ selected.filename }}</el-descriptions-item><el-descriptions-item label="包数">{{ selected.packet_count }}</el-descriptions-item><el-descriptions-item label="时长">{{ formatDuration(selected.duration) }}</el-descriptions-item><el-descriptions-item label="状态">{{ selected.status }}</el-descriptions-item></el-descriptions>
        <el-tabs v-model="active" class="tabs">
          <el-tab-pane label="Overview" name="overview">
            <el-descriptions :column="4" border><el-descriptions-item label="Flows">{{ flows.length }}</el-descriptions-item><el-descriptions-item label="Packets">{{ packets.length }}</el-descriptions-item><el-descriptions-item label="Alerts">{{ alerts.length }}</el-descriptions-item><el-descriptions-item label="Protocols">{{ Object.keys(selected.protocol_summary || {}).length }}</el-descriptions-item></el-descriptions>
            <div ref="trafficEl" class="chart" />
            <el-divider content-position="left">Top Talkers</el-divider>
            <el-table :data="traffic?.top_n || []" size="small"><el-table-column label="src → dst"><template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }} → {{ row.dst_ip }}:{{ row.dst_port }}</template></el-table-column><el-table-column prop="bytes" label="字节" /><el-table-column prop="packets" label="包数" /></el-table>
            <JsonViewer :value="selected.protocol_summary" title="查看协议摘要" />
          </el-tab-pane>
          <el-tab-pane label="Flows" name="flows"><el-table :data="flows" size="small"><el-table-column label="src → dst"><template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }} → {{ row.dst_ip }}:{{ row.dst_port }}</template></el-table-column><el-table-column prop="protocol" label="协议" /><el-table-column prop="packets" label="包数" /><el-table-column prop="bytes" label="字节" /><el-table-column prop="duration" label="时长" /></el-table></el-tab-pane>
          <el-tab-pane label="Packets" name="packets"><el-table :data="packets" size="small"><el-table-column prop="number" label="#" /><el-table-column prop="timestamp" label="Time" /><el-table-column prop="src_ip" label="Src" /><el-table-column prop="dst_ip" label="Dst" /><el-table-column prop="protocol" label="协议" /><el-table-column prop="length" label="Len" /><el-table-column prop="info" label="Info" /></el-table></el-tab-pane>
          <el-tab-pane label="Protocols" name="protocols"><JsonViewer :value="selected.protocol_summary" title="协议分布" /></el-tab-pane>
          <el-tab-pane label="DNS" name="dns"><el-table :data="dns" size="small"><el-table-column v-for="key in ['query', 'qname', 'rrname', 'name']" :key="key" :prop="key" :label="key" /><el-table-column v-for="key in ['type', 'rcode']" :key="key" :prop="key" :label="key" /></el-table></el-tab-pane>
          <el-tab-pane label="HTTP" name="http"><el-table :data="http" size="small"><el-table-column v-for="key in ['method', 'uri', 'host', 'status', 'user_agent']" :key="key" :prop="key" :label="key" /></el-table></el-tab-pane>
          <el-tab-pane label="TLS" name="tls"><el-table :data="tls" size="small"><el-table-column v-for="key in ['server_name', 'sni', 'cipher', 'ja3']" :key="key" :prop="key" :label="key" /></el-table></el-tab-pane>
          <el-tab-pane label="Files" name="files"><el-table :data="files" size="small"><el-table-column v-for="key in ['filename', 'name', 'mime_type', 'magic']" :key="key" :prop="key" :label="key" /></el-table></el-tab-pane>
          <el-tab-pane label="Alerts" name="alerts"><el-table :data="alerts" size="small"><el-table-column prop="source" label="来源" /><el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column><el-table-column prop="title" label="标题" /><el-table-column prop="description" label="描述" /></el-table></el-tab-pane>
        </el-tabs>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.pagination { margin-top: 14px; justify-content: flex-end; }
.tabs { margin-top: 12px; }
.chart { height: 260px; }
</style>
