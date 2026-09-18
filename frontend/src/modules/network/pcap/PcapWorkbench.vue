<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { listPcaps, getPcap, analyzePcap, uploadPcap, getPcapFlows, getPcapPackets, getPcapAlerts, getPcapDns, getPcapHttp, getPcapTls, getPcapFiles, getTraffic, getPcapProtocols, getPcapAnomalies, getPcapPacketDetail, getPcapStream, type PacketDetail } from '../../../api/pcaps'
import type { PcapRecord, Flow, Packet, AlertItem, TrafficOverview, NetworkFile, ProtocolLayer } from '../../../types/pcap'
import StateBox from '../../../components/common/StateBox.vue'
import PacketViewer from '../../../components/network/PacketViewer.vue'
import FlowTable from '../../../components/network/FlowTable.vue'
import ProtocolTree, { type Layer } from '../../../components/network/ProtocolTree.vue'
import HexViewer from '../../../components/evidence/HexViewer.vue'
import RawViewer from '../../../components/evidence/RawViewer.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import StatusBadge from '../../../components/security/StatusBadge.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { formatBytes, formatDateTime, formatDuration } from '../../../utils/format'
import { getPcapFilePreview, getPcapFileDownloadUrl, type FilePreview } from '../../../api/pcaps'
import { getTask } from '../../../api/tasks'

const evidenceDialog = ref(false)
const alertEvidence = ref<unknown>(null)
const loading = ref(true)
const error = ref('')
const items = ref<PcapRecord[]>([])
const total = ref(0)
const selected = ref<PcapRecord | null>(null)
const activeTab = ref('overview')
const flows = ref<Flow[]>([])
const packets = ref<Packet[]>([])
const alerts = ref<AlertItem[]>([])
const dns = ref<Array<Record<string, unknown>>>([])
const http = ref<Array<Record<string, unknown>>>([])
const tls = ref<Array<Record<string, unknown>>>([])
const files = ref<NetworkFile[]>([])
const traffic = ref<TrafficOverview | null>(null)
const protocolTree = ref<Array<Record<string, unknown>>>([])

// The overview panel shows the same application-layer view as the protocol
// analysis page: the raw summary counts every frame layer (sll, ethertype,
// ip, tcp), which is not a protocol distribution an operator can read.
const applicationProtocols = computed(() =>
  protocolTree.value
    .filter((node: any) => (node.layer || 'application') === 'application')
    .map((node: any) => ({ name: node.name, count: node.count })),
)
const anomalies = ref<Array<Record<string, unknown>>>([])
const selectedPacket = ref<Packet | null>(null)
const packetDetail = ref<PacketDetail | null>(null)
const packetDetailLoading = ref(false)
const uploadProgress = ref<number | null>(null)
const packetQuery = reactive({ page: 1, pageSize: 100, search: '' })
const packetTotal = ref(0)
const flowTotal = ref(0)
const packetLoading = ref(false)
const packetError = ref('')
const fileNeedsAnalysis = ref(false)
const fileCoverage = ref<Record<string, unknown>>({})
const filePreview = ref<FilePreview | null>(null)
const fileDialog = ref(false)
const fileLoading = ref(false)
const fileError = ref('')
const activeFile = ref<NetworkFile | null>(null)
const analyzingId = ref<number | null>(null)
const analysisStage = ref('')
let viewVersion = 0
let packetVersion = 0
let detailVersion = 0
let fileVersion = 0
let taskVersion = 0
let taskTimer: ReturnType<typeof setTimeout> | undefined
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })

const packetLayers = computed<Layer[]>(() => {
  return packetDetail.value?.layers || []
})

const packetHex = computed(() => packetDetail.value?.raw || '')
const packetText = computed(() => {
  const hex = packetHex.value
  if (!hex) return ''
  return new TextDecoder().decode(Uint8Array.from(hex.match(/.{2}/g) || [], (b) => parseInt(b, 16)))
})
const extractionLimited = computed(() => Object.entries(fileCoverage.value).some(
  ([key, value]) => value && (key.endsWith('_limit') || key.endsWith('_error') || key.endsWith('_timeout') || key.endsWith('_incomplete')),
))

const selectedTcpStream = computed<number | null>(() => {
  const tcp = packetDetail.value?.layers.find((layer) => layer.name === 'TCP')
  const item = tcp?.items.find((i) => i.label === 'stream')
  if (!item) return null
  const value = Number(item.value)
  return Number.isFinite(value) ? value : null
})

const dnsColumns = ['query', 'qname', 'rrname', 'name', 'type', 'rcode', 'source']
const httpColumns = ['method', 'uri', 'host', 'status', 'user_agent', 'source']
const tlsColumns = ['server_name', 'sni', 'cipher', 'ja3', 'version', 'source']

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

async function openPcap(row: PcapRecord): Promise<void> {
  const version = ++viewVersion
  ++detailVersion
  ++fileVersion
  fileDialog.value = false
  selectedPacket.value = null
  packetDetail.value = null
  packets.value = []
  files.value = []
  flows.value = []
  alerts.value = []
  dns.value = []
  http.value = []
  tls.value = []
  traffic.value = null
  protocolTree.value = []
  anomalies.value = []
  packetTotal.value = flowTotal.value = 0
  fileNeedsAnalysis.value = false
  fileCoverage.value = {}
  packetQuery.page = 1
  packetQuery.search = ''
  try {
    const capture = await getPcap(row.id)
    if (version !== viewVersion) return
    selected.value = capture
    activeTab.value = 'overview'
    const apply = (action: () => void) => { if (version === viewVersion) action() }
    await Promise.all([
      getPcapFlows(row.id).then((v) => apply(() => { flows.value = v.items; flowTotal.value = v.total })),
      loadPackets(),
      getPcapAlerts(row.id).then((v) => apply(() => { alerts.value = v.items })),
      getPcapDns(row.id).then((v) => apply(() => { dns.value = v.items })),
      getPcapHttp(row.id).then((v) => apply(() => { http.value = v.items })),
      getPcapTls(row.id).then((v) => apply(() => { tls.value = v.items })),
      getPcapFiles(row.id).then((v) => apply(() => {
        files.value = v.items; fileNeedsAnalysis.value = !!v.needs_analysis; fileCoverage.value = v.coverage || {}
      })),
      getPcapProtocols(row.id).then((v) => apply(() => { protocolTree.value = v })),
      getPcapAnomalies(row.id).then((v) => apply(() => { anomalies.value = v })),
      getTraffic(row.id).then((v) => apply(() => { traffic.value = v })),
    ])
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function runAnalyze(row: PcapRecord): Promise<void> {
  try {
    const task = await analyzePcap(row.id)
    trackTask(task.id, row.id)
    ElMessage.success('已触发分析')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function handleUpload(file: File): Promise<void> {
  if (!file || uploadProgress.value !== null) return
  if (!file.size) { ElMessage.error('抓包文件为空'); return }
  uploadProgress.value = 0
  try {
    const result = await uploadPcap(file, undefined, (percent) => { uploadProgress.value = percent })
    ElMessage.success(result.duplicate ? `文件已存在，已定位到记录 #${result.id}` : 'PCAP 已上传，正在分析')
    filters.page = 1
    filters.search = ''
    filters.status = ''
    await openPcap({ id: result.id } as PcapRecord)
    if (result.task_id) trackTask(result.task_id, result.id)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    uploadProgress.value = null
  }
}

async function selectPacket(packet: Packet): Promise<void> {
  const version = ++detailVersion
  selectedPacket.value = packet
  activeTab.value = 'packets'
  packetDetail.value = null
  if (!selected.value) return
  packetDetailLoading.value = true
  try {
    const detail = await getPcapPacketDetail(selected.value.id, packet.id)
    if (version === detailVersion) packetDetail.value = detail
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    if (version === detailVersion) packetDetailLoading.value = false
  }
}

async function loadPackets(): Promise<void> {
  const id = selected.value?.id
  if (!id) return
  const version = ++packetVersion
  ++detailVersion
  selectedPacket.value = null
  packetDetail.value = null
  packetLoading.value = true
  packetError.value = ''
  try {
    const result = await getPcapPackets(id, packetQuery.page, packetQuery.pageSize, packetQuery.search)
    if (version !== packetVersion || selected.value?.id !== id) return
    packets.value = result.items
    packetTotal.value = result.total
  } catch (err) {
    if (version === packetVersion) packetError.value = err instanceof Error ? err.message : String(err)
  } finally {
    if (version === packetVersion) packetLoading.value = false
  }
}

async function showFile(file: NetworkFile, offset = 0): Promise<void> {
  if (!selected.value || !file.id || !file.binary_available) return
  const version = ++fileVersion
  activeFile.value = file
  filePreview.value = null
  fileDialog.value = true
  fileLoading.value = true
  fileError.value = ''
  try {
    const result = await getPcapFilePreview(selected.value.id, file.id, offset)
    if (version === fileVersion) filePreview.value = result
  } catch (err) {
    if (version === fileVersion) fileError.value = err instanceof Error ? err.message : String(err)
  } finally {
    if (version === fileVersion) fileLoading.value = false
  }
}

function trackTask(taskId: number, pcapId: number): void {
  const version = ++taskVersion
  clearTimeout(taskTimer)
  analyzingId.value = pcapId
  analysisStage.value = '分析排队中'
  const poll = async () => {
    try {
      const task = await getTask(taskId)
      if (version !== taskVersion) return
      analysisStage.value = `${task.current_stage} ${task.progress}%`
      if (['Success', 'Failed', 'Stopped', 'Cancelled'].includes(task.status)) {
        analyzingId.value = null
        if (task.status === 'Success') {
          if (selected.value?.id === pcapId) {
            const tab = activeTab.value
            await openPcap(selected.value)
            if (selected.value?.id === pcapId) activeTab.value = tab
          } else await load()
        } else ElMessage.error(task.error || '分析未完成，请查看任务中心')
        return
      }
    } catch (err) {
      if (version !== taskVersion) return
      analysisStage.value = '暂时无法获取分析状态'
    }
    if (version === taskVersion) taskTimer = setTimeout(poll, 3000)
  }
  void poll()
}

const streamDialog = ref(false)
const streamData = ref<{ stream: string; nodes: Array<{ node: number; ip: string; port: number }>; directions: Array<{ direction: string; ascii: string; hex: string }> } | null>(null)
const streamLoading = ref(false)

async function followStream(streamId: number): Promise<void> {
  if (!selected.value) return
  streamLoading.value = true
  try {
    streamData.value = await getPcapStream(selected.value.id, streamId)
    streamDialog.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    streamLoading.value = false
  }
}

function reset(): void { filters.page = 1; load() }
function back(): void { ++viewVersion; ++packetVersion; ++detailVersion; selected.value = null; void load() }

onMounted(load)
onUnmounted(() => { ++viewVersion; ++packetVersion; ++detailVersion; ++fileVersion; ++taskVersion; clearTimeout(taskTimer) })
</script>

<template>
  <div class="pcap-workbench">
    <!-- Pcap selector / list -->
    <div v-if="!selected" class="wb-list">
      <div class="toolbar">
        <el-upload accept=".pcap,.pcapng,.cap" :auto-upload="false" :show-file-list="false" :disabled="uploadProgress !== null" :on-change="(file: any) => handleUpload(file.raw as File)">
          <el-button type="primary" :loading="uploadProgress !== null">{{ uploadProgress === null ? '上传 PCAP/PCAPNG' : uploadProgress === 100 ? '服务器接收中' : `上传中 ${uploadProgress}%` }}</el-button>
        </el-upload>
        <el-input v-model="filters.search" placeholder="搜索文件名" clearable @keyup.enter="reset" />
        <el-select v-model="filters.status" placeholder="状态" clearable><el-option v-for="s in ['pending', 'analyzed', 'failed', 'retained_analysis']" :key="s" :label="s" :value="s" /></el-select>
        <el-button @click="reset">查询</el-button>
        <div class="toolbar-spacer" />
        <span class="text-muted">共 {{ total }} 个 PCAP</span>
      </div>
      <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
        <el-table :data="items" size="small" @row-click="openPcap">
          <el-table-column prop="filename" label="文件" min-width="200" show-overflow-tooltip />
          <el-table-column label="大小" width="100"><template #default="{ row }">{{ formatBytes(row.size) }}</template></el-table-column>
          <el-table-column label="包数" width="90"><template #default="{ row }">{{ row.total_packet_count ?? row.packet_count }}</template></el-table-column>
          <el-table-column label="时长" width="90"><template #default="{ row }">{{ formatDuration(row.duration) }}</template></el-table-column>
          <el-table-column label="捕获时间" width="160"><template #default="{ row }">{{ formatDateTime(row.capture_start) }}</template></el-table-column>
          <el-table-column prop="status" label="状态" width="110" />
          <el-table-column label="操作" width="140"><template #default="{ row }"><el-button size="small" @click.stop="runAnalyze(row)">分析</el-button><el-button size="small" type="primary" @click.stop="openPcap(row)">打开</el-button></template></el-table-column>
        </el-table>
        <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
      </StateBox>
    </div>

    <!-- Workbench -->
    <div v-else class="wb-main">
      <div class="wb-toolbar">
        <el-button text @click="back"><el-icon><Back /></el-icon> 返回</el-button>
        <div class="wb-name mono">{{ selected.filename }}</div>
        <StatusBadge :value="selected.status" />
        <div class="toolbar-spacer" />
        <span class="text-dim">{{ selected.total_packet_count ?? selected.packet_count }} pkts · {{ formatBytes(selected.size) }} · {{ formatDuration(selected.duration) }}</span>
        <span v-if="analyzingId === selected.id" class="text-dim">{{ analysisStage }}</span>
        <el-button size="small" :loading="analyzingId === selected.id" @click="runAnalyze(selected)">重新分析</el-button>
      </div>

      <el-tabs v-model="activeTab" class="wb-tabs">
        <el-tab-pane label="总览" name="overview">
          <div class="grid cols-4">
            <div class="soc-card"><div class="mini-label">会话流</div><div class="mini-value">{{ flowTotal }}</div></div>
            <div class="soc-card"><div class="mini-label">数据包</div><div class="mini-value">{{ selected.total_packet_count ?? selected.packet_count }}</div></div>
            <div class="soc-card"><div class="mini-label">告警</div><div class="mini-value" style="color:var(--soc-danger)">{{ alerts.length }}</div></div>
            <div class="soc-card"><div class="mini-label">文件</div><div class="mini-value">{{ files.length }}</div></div>
          </div>
          <div class="grid cols-2" style="margin-top: 12px">
            <div class="soc-card">
              <div class="soc-card-title"><span class="dot" />流量趋势</div>
              <RawViewer :value="JSON.stringify(traffic?.trend || [], null, 2)" language="json" :height="280" />
            </div>
            <div class="soc-card">
              <div class="soc-card-title"><span class="dot warn" />Top 通信对</div>
              <FlowTable :flows="traffic?.top_n || []" />
            </div>
          </div>
          <div class="soc-card" style="margin-top: 12px">
            <div class="soc-card-title"><span class="dot" />协议摘要</div>
            <JsonViewer :value="applicationProtocols" title="协议分布（应用层协议）" :height="240" />
          </div>
        </el-tab-pane>

        <el-tab-pane label="数据包" name="packets" lazy>
          <!-- Three-pane packet explorer -->
          <div class="packet-explorer">
            <div class="pe-pane pe-list">
              <div class="packet-toolbar">
                <span class="pe-title">数据包列表</span>
                <el-input v-model="packetQuery.search" clearable placeholder="地址、协议或包信息" @keyup.enter="packetQuery.page = 1; loadPackets()" @clear="packetQuery.page = 1; loadPackets()" />
                <el-button @click="packetQuery.page = 1; loadPackets()">查询</el-button>
                <span class="text-dim">已索引 {{ selected.indexed_packet_count ?? packetTotal }} / {{ selected.total_packet_count ?? selected.packet_count }}</span>
              </div>
              <el-alert v-if="packetError" :title="packetError" type="error" :closable="false" />
              <PacketViewer v-loading="packetLoading" :packets="packets" :selected="selectedPacket?.id" @select="selectPacket" />
              <el-pagination class="packet-pagination" layout="total, sizes, prev, pager, next" :total="packetTotal" :page-sizes="[50, 100, 250, 500]" v-model:page-size="packetQuery.pageSize" v-model:current-page="packetQuery.page" @current-change="loadPackets" @size-change="packetQuery.page = 1; loadPackets()" />
            </div>
            <div class="pe-pane pe-tree">
              <div class="pe-title">协议分层树</div>
              <ProtocolTree v-if="selectedPacket" :layers="packetLayers" />
              <div v-else class="pe-empty">选择左侧数据包查看协议分层</div>
            </div>
            <div class="pe-pane pe-raw">
              <div class="pe-title">原始视图</div>
              <div v-if="selectedPacket" class="pe-raw-body">
                <el-tabs>
                  <el-tab-pane label="包信息">
                    <el-descriptions :column="1" border size="small">
                      <el-descriptions-item label="序号">{{ selectedPacket.number }}</el-descriptions-item>
                      <el-descriptions-item label="时间">{{ formatDateTime(selectedPacket.timestamp) }}</el-descriptions-item>
                      <el-descriptions-item label="源地址">{{ selectedPacket.src_ip }}:{{ selectedPacket.src_port }}</el-descriptions-item>
                      <el-descriptions-item label="目的地址">{{ selectedPacket.dst_ip }}:{{ selectedPacket.dst_port }}</el-descriptions-item>
                      <el-descriptions-item label="协议">{{ selectedPacket.protocol }}</el-descriptions-item>
                      <el-descriptions-item label="长度">{{ selectedPacket.length }}</el-descriptions-item>
                      <el-descriptions-item label="信息">{{ selectedPacket.info }}</el-descriptions-item>
                    </el-descriptions>
                  </el-tab-pane>
                  <el-tab-pane label="Hex">
                    <HexViewer :data="packetHex" />
                    <div v-if="packetDetailLoading" class="gap-note">加载原始字节中…</div>
                    <div v-else-if="!packetHex" class="gap-note">该数据包无可用原始字节</div>
                  </el-tab-pane>
                  <el-tab-pane label="文本">
                    <pre class="stream-pre">{{ packetText || '无可用字节' }}</pre>
                  </el-tab-pane>
                  <el-tab-pane label="流跟踪">
                    <div class="pe-actions">
                      <el-button size="small" type="primary" :loading="streamLoading" :disabled="selectedTcpStream === null" @click="followStream(selectedTcpStream!)">Follow TCP Stream</el-button>
                      <span class="text-dim">{{ selectedTcpStream === null ? '非 TCP 数据包或无会话' : `TCP Stream ${selectedTcpStream}` }}</span>
                    </div>
                  </el-tab-pane>
                </el-tabs>
              </div>
              <div v-else class="pe-empty">选择左侧数据包查看原始字节</div>
            </div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="会话流" name="flows">
          <div class="soc-card"><FlowTable :flows="flows" /></div>
        </el-tab-pane>

        <el-tab-pane label="协议" name="protocols">
          <div class="soc-card"><JsonViewer :value="protocolTree" title="协议分层树" :height="400" /></div>
        </el-tab-pane>

        <el-tab-pane label="DNS" name="dns">
          <div class="soc-card">
            <el-table :data="dns" size="small">
              <el-table-column v-for="key in dnsColumns" :key="key" :prop="key" :label="key" min-width="120" show-overflow-tooltip />
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane label="HTTP" name="http">
          <div class="soc-card">
            <el-table :data="http" size="small">
              <el-table-column v-for="key in httpColumns" :key="key" :prop="key" :label="key" min-width="120" show-overflow-tooltip />
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane label="TLS" name="tls">
          <div class="soc-card">
            <el-table :data="tls" size="small">
              <el-table-column v-for="key in tlsColumns" :key="key" :prop="key" :label="key" min-width="120" show-overflow-tooltip />
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane label="文件" name="files">
          <div class="soc-card">
            <el-alert v-if="fileNeedsAnalysis" title="此抓包尚未保存提取文件，请点击重新分析。" type="info" :closable="false" />
            <el-alert v-if="extractionLimited" title="部分数据达到提取限制或解析未完成，以下展示已保留内容。" type="warning" :closable="false" />
            <div v-if="Number(fileCoverage.encrypted_streams) > 0" class="gap-note">{{ fileCoverage.encrypted_streams }} 条加密流无法还原文件明文</div>
            <el-table :data="files" size="small">
              <el-table-column label="文件名" min-width="220" show-overflow-tooltip><template #default="{ row }">{{ row.filename || row.name || row.fuid || '-' }}</template></el-table-column>
              <el-table-column prop="mime_type" label="类型" min-width="160" show-overflow-tooltip />
              <el-table-column label="大小" width="100"><template #default="{ row }">{{ formatBytes(row.size || row.seen_bytes || 0) }}</template></el-table-column>
              <el-table-column prop="source" label="协议/来源" width="115" />
              <el-table-column label="完整性" width="110"><template #default="{ row }">{{ row.complete === true ? '完整' : row.complete === false ? '捕获片段' : '未校验' }}</template></el-table-column>
              <el-table-column prop="sha256" label="SHA256" min-width="180" show-overflow-tooltip />
              <el-table-column label="内容" width="140"><template #default="{ row }">
                <el-button link type="primary" :disabled="!row.binary_available" @click="showFile(row)">查看</el-button>
                <a v-if="row.binary_available && row.id" :href="getPcapFileDownloadUrl(selected.id, row.id)" class="file-download">下载</a>
                <span v-else class="text-dim">未保留</span>
              </template></el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane label="告警" name="alerts">
          <div class="soc-card">
            <el-table :data="alerts" size="small">
              <el-table-column prop="source" label="来源" width="120" />
              <el-table-column label="等级" width="100"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
              <el-table-column prop="title" label="标题" min-width="180" show-overflow-tooltip />
              <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
              <el-table-column label="证据" width="90"><template #default="{ row }"><el-button link type="primary" :disabled="!row.evidence" @click.stop="alertEvidence = row.evidence; evidenceDialog = true">查看证据</el-button></template></el-table-column>
            </el-table>
          </div>
        </el-tab-pane>

        <el-tab-pane label="时间线" name="timeline">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />异常时间线</div>
            <el-timeline v-if="anomalies.length">
              <el-timeline-item v-for="(a, i) in anomalies" :key="i" :timestamp="a.timestamp" :color="a.severity === 'High' ? '#ef4444' : '#eab308'">
                {{ a.rule }} <span class="text-dim">({{ a.severity }})</span>
              </el-timeline-item>
            </el-timeline>
            <div v-else class="text-dim">无异常记录</div>
          </div>
        </el-tab-pane>

        <el-tab-pane label="原始证据" name="raw">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />原始证据</div>
            <RawViewer :value="JSON.stringify({ pcap: selected, flows: flows.slice(0, 50), alerts, anomalies }, null, 2)" language="json" :height="520" />
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>

    <el-dialog v-model="fileDialog" title="传输文件内容" width="min(1100px, 95vw)" @closed="++fileVersion">
      <div v-if="activeFile" class="file-meta">
        <strong>{{ activeFile.filename }}</strong>
        <span>{{ formatBytes(activeFile.size || 0) }} · {{ activeFile.mime_type }}</span>
        <a v-if="selected && activeFile.id" :href="getPcapFileDownloadUrl(selected.id, activeFile.id)">下载提取文件</a>
      </div>
      <el-alert v-if="fileError" :title="fileError" type="error" :closable="false" />
      <div v-loading="fileLoading" class="file-preview">
        <template v-if="filePreview">
          <el-tabs>
            <el-tab-pane label="文本">
              <div class="text-dim">{{ filePreview.encoding }}{{ filePreview.binary ? ' · 包含二进制数据，可切换 Hex 查看原始字节' : '' }}</div>
              <pre class="stream-pre file-text">{{ filePreview.text }}</pre>
            </el-tab-pane>
            <el-tab-pane label="Hex / ASCII"><HexViewer :data="filePreview.hex" :offset="filePreview.offset" /></el-tab-pane>
          </el-tabs>
          <div class="file-page">
            <el-button :disabled="!filePreview.offset" @click="showFile(activeFile!, Math.max(0, filePreview!.offset - 16384))">上一段</el-button>
            <span>{{ filePreview.offset }} - {{ filePreview.offset + filePreview.length }} / {{ filePreview.size }} 字节</span>
            <el-button :disabled="!filePreview.has_more" @click="showFile(activeFile!, filePreview!.offset + filePreview!.length)">下一段</el-button>
          </div>
        </template>
      </div>
    </el-dialog>

    <el-dialog v-model="streamDialog" title="TCP Stream 跟踪" width="70%">
      <div v-if="streamData" class="stream-dialog">
        <div class="text-dim mono" style="margin-bottom: 8px">
          {{ streamData.nodes[0]?.ip }}:{{ streamData.nodes[0]?.port }} ⇄ {{ streamData.nodes[1]?.ip }}:{{ streamData.nodes[1]?.port }}
        </div>
        <el-tabs>
          <el-tab-pane label="ASCII">
            <pre class="stream-pre">{{ streamData.directions.map((d) => d.ascii).join('\n\n---\n\n') || '（空）' }}</pre>
          </el-tab-pane>
          <el-tab-pane label="Hex">
            <pre class="stream-pre">{{ streamData.directions.map((d) => d.hex).join('\n\n---\n\n') || '（空）' }}</pre>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>
  </div>
<el-dialog v-model="evidenceDialog" title="告警证据" width="min(900px, 90vw)" append-to-body><JsonViewer :value="alertEvidence" :height="480" /></el-dialog>
</template>

<style scoped>
.pcap-workbench { height: calc(100vh - var(--soc-header-h) - 32px); display: flex; flex-direction: column; }
.wb-list { flex: 1; overflow: auto; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; }
.wb-main { flex: 1; display: flex; flex-direction: column; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; overflow: auto; }
.wb-toolbar { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
.wb-name { font-weight: 700; color: var(--soc-text-strong); min-width: 0; overflow-wrap: anywhere; flex: 1; }
.wb-tabs { flex: 1; display: flex; flex-direction: column; }
.wb-tabs :deep(.el-tabs__content) { flex: 1; overflow: auto; }
.packet-explorer { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr); grid-template-rows: minmax(300px, 46vh) minmax(280px, 38vh); gap: 12px; min-width: 0; }
.pe-pane { border: 1px solid var(--soc-border); border-radius: var(--soc-radius-sm); padding: 10px; display: flex; flex-direction: column; overflow: auto; min-width: 0; min-height: 0; }
.pe-title { font-size: 12px; font-weight: 700; color: var(--soc-text-muted); margin-bottom: 8px; }
.pe-list { grid-column: 1 / -1; overflow: hidden; }
.pe-list :deep(.el-table) { flex: 1; min-height: 0; }
.packet-toolbar { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
.packet-toolbar .el-input { width: 260px; max-width: 100%; }
.packet-toolbar .pe-title { margin: 0; }
.packet-pagination { margin-top: 8px; flex-shrink: 0; max-width: 100%; overflow: auto; }
.file-meta, .file-page { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin: 12px 0; overflow-wrap: anywhere; }
.file-preview { min-height: 200px; }
.file-preview :deep(.hex-viewer), .file-text { max-height: 52vh; overflow: auto; }
.file-download { margin-left: 12px; color: var(--soc-primary); }
@media (max-width: 800px) {
  .packet-explorer { grid-template-columns: minmax(0, 1fr); grid-template-rows: 400px 280px 360px; }
  .pe-list { grid-column: 1; }
  .wb-list .toolbar { flex-wrap: wrap; }
}
.pe-raw-body { flex: 1; overflow: auto; }
.pe-empty { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--soc-text-dim); font-size: 12px; }
.mini-label { color: var(--soc-text-muted); font-size: 12px; }
.mini-value { font-size: 26px; font-weight: 700; color: var(--soc-text-strong); margin-top: 6px; }
.gap-note { color: var(--soc-warning); font-size: 11px; margin-top: 8px; }
.pe-actions { display: flex; align-items: center; gap: 12px; margin-top: 8px; }
.stream-dialog { max-height: 60vh; overflow: auto; }
.stream-pre { font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; background: var(--soc-bg); padding: 10px; border-radius: var(--soc-radius-sm); border: 1px solid var(--soc-border); }
</style>
