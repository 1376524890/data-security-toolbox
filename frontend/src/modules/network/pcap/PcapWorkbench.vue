<script setup lang="ts">
import { onMounted, reactive, ref, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { listPcaps, getPcap, analyzePcap, uploadPcap, getPcapFlows, getPcapPackets, getPcapAlerts, getPcapDns, getPcapHttp, getPcapTls, getPcapFiles, getTraffic, getPcapProtocols, getPcapAnomalies } from '../../../api/pcaps'
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
const anomalies = ref<Array<Record<string, unknown>>>([])
const selectedPacket = ref<Packet | null>(null)
const filters = reactive({ search: '', status: '', page: 1, page_size: 50 })

const packetLayers = computed<Layer[]>(() => {
  const p = selectedPacket.value
  if (!p) return []
  const layers: Layer[] = []
  layers.push({ name: 'Ethernet II', items: [
    { label: 'Source MAC', value: '—' },
    { label: 'Destination MAC', value: '—' },
    { label: 'Type', value: 'IPv4 (0x0800)' },
  ] })
  layers.push({ name: 'Internet Protocol Version 4', items: [
    { label: 'Version', value: '4' },
    { label: 'Source', value: p.src_ip },
    { label: 'Destination', value: p.dst_ip },
    { label: 'Protocol', value: p.protocol },
    { label: 'Length', value: String(p.length) },
  ] })
  if (p.src_port || p.dst_port) {
    layers.push({ name: p.protocol.toUpperCase(), items: [
      { label: 'Source Port', value: String(p.src_port) },
      { label: 'Destination Port', value: String(p.dst_port) },
      { label: 'Info', value: p.info || '—' },
    ] })
  }
  layers.push({ name: 'Raw Payload', note: '原始字节与深层协议解析需要后端 packet-detail 接口（已记录为前端缺口）', items: [] })
  return layers
})

const packetHex = computed(() => selectedPacket.value ? '' : '')

const dnsColumns = ['query', 'qname', 'rrname', 'name', 'type', 'rcode', 'source']
const httpColumns = ['method', 'uri', 'host', 'status', 'user_agent', 'source']
const tlsColumns = ['server_name', 'sni', 'cipher', 'ja3', 'version', 'source']
const fileColumns = ['filename', 'name', 'mime_type', 'magic', 'size', 'sha256', 'source']

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
  try {
    selected.value = await getPcap(row.id)
    activeTab.value = 'overview'
    selectedPacket.value = null
    await Promise.all([
      getPcapFlows(row.id).then((v) => { flows.value = v.items }),
      getPcapPackets(row.id).then((v) => { packets.value = v.items }),
      getPcapAlerts(row.id).then((v) => { alerts.value = v.items }),
      getPcapDns(row.id).then((v) => { dns.value = v.items }),
      getPcapHttp(row.id).then((v) => { http.value = v.items }),
      getPcapTls(row.id).then((v) => { tls.value = v.items }),
      getPcapFiles(row.id).then((v) => { files.value = v.items }),
      getPcapProtocols(row.id).then((v) => { protocolTree.value = v }),
      getPcapAnomalies(row.id).then((v) => { anomalies.value = v }),
      getTraffic(row.id).then((v) => { traffic.value = v }),
    ])
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

async function handleUpload(file: File): Promise<void> {
  try {
    await uploadPcap(file)
    ElMessage.success('PCAP 已上传')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function selectPacket(packet: Packet): void {
  selectedPacket.value = packet
  activeTab.value = 'packets'
}

function reset(): void { filters.page = 1; load() }
function back(): void { selected.value = null }

onMounted(load)
</script>

<template>
  <div class="pcap-workbench">
    <!-- Pcap selector / list -->
    <div v-if="!selected" class="wb-list">
      <div class="toolbar">
        <el-upload :auto-upload="false" :show-file-list="false" :on-change="(file: any) => handleUpload(file.raw as File)">
          <el-button type="primary">上传 PCAP/PCAPNG</el-button>
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
        <el-button size="small" @click="runAnalyze(selected)">重新分析</el-button>
      </div>

      <el-tabs v-model="activeTab" class="wb-tabs">
        <el-tab-pane label="总览" name="overview">
          <div class="grid cols-4">
            <div class="soc-card"><div class="mini-label">会话流</div><div class="mini-value">{{ flows.length }}</div></div>
            <div class="soc-card"><div class="mini-label">数据包</div><div class="mini-value">{{ packets.length }}</div></div>
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
            <JsonViewer :value="selected.protocol_summary" title="协议分布" :height="240" />
          </div>
        </el-tab-pane>

        <el-tab-pane label="数据包" name="packets">
          <!-- Three-pane packet explorer -->
          <div class="packet-explorer">
            <div class="pe-pane pe-list">
              <div class="pe-title">数据包列表</div>
              <PacketViewer :packets="packets" :selected="selectedPacket?.id" @select="selectPacket" />
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
                    <div class="gap-note">原始字节需后端 packet-detail 接口（缺口已记录）</div>
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
            <el-table :data="files" size="small">
              <el-table-column v-for="key in fileColumns" :key="key" :prop="key" :label="key" min-width="120" show-overflow-tooltip />
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
              <el-table-column label="证据" width="90"><template #default="{ row }"><JsonViewer :value="row.evidence" title="查看" :height="200" /></template></el-table-column>
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
  </div>
</template>

<style scoped>
.pcap-workbench { height: calc(100vh - var(--soc-header-h) - 32px); display: flex; flex-direction: column; }
.wb-list { flex: 1; overflow: auto; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; }
.wb-main { flex: 1; display: flex; flex-direction: column; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; overflow: auto; }
.wb-toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.wb-name { font-weight: 700; color: var(--soc-text-strong); }
.wb-tabs { flex: 1; display: flex; flex-direction: column; }
.wb-tabs :deep(.el-tabs__content) { flex: 1; overflow: auto; }
.packet-explorer { display: grid; grid-template-columns: 32% 34% 34%; gap: 12px; height: calc(100vh - var(--soc-header-h) - 170px); }
.pe-pane { border: 1px solid var(--soc-border); border-radius: var(--soc-radius-sm); padding: 10px; display: flex; flex-direction: column; overflow: hidden; }
.pe-title { font-size: 12px; font-weight: 700; color: var(--soc-text-muted); margin-bottom: 8px; }
.pe-list, .pe-tree { }
.pe-list :deep(.el-table) { flex: 1; }
.pe-raw-body { flex: 1; overflow: auto; }
.pe-empty { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--soc-text-dim); font-size: 12px; }
.mini-label { color: var(--soc-text-muted); font-size: 12px; }
.mini-value { font-size: 26px; font-weight: 700; color: var(--soc-text-strong); margin-top: 6px; }
.gap-note { color: var(--soc-warning); font-size: 11px; margin-top: 8px; }
</style>
