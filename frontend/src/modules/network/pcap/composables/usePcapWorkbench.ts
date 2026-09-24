/**
 * PCAP workbench state: the capture list, upload/analysis tracking and every
 * panel the workbench shows for one capture (flows, packets, protocols, files,
 * alerts, anomalies).
 *
 * The view keeps the template, the dialogs and the formatting helpers; the API
 * calls and the page state live here.  The version counters drop stale
 * responses when the operator switches capture, packet page or file faster
 * than the API answers, and the analysis poll keeps asking ``getTask`` until a
 * terminal status before refreshing the open capture.
 */
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  analyzePcap,
  getPcap,
  getPcapAlerts,
  getPcapAnomalies,
  getPcapDns,
  getPcapFilePreview,
  getPcapFiles,
  getPcapFlows,
  getPcapHttp,
  getPcapPacketDetail,
  getPcapPackets,
  getPcapProtocols,
  getPcapStream,
  getPcapTls,
  getTraffic,
  listPcaps,
  uploadPcap,
  type FilePreview,
  type PacketDetail,
  type TcpStreamFollow,
} from '../../../../api/pcaps'
import { getTask } from '../../../../api/tasks'
import { useAutoRefresh } from '../../../../composables/useAutoRefresh'
import { useTableSort } from '../../../../composables/useTableSort'
import type { Layer } from '../../../../components/network/ProtocolTree.vue'
import type { AlertItem, Flow, NetworkFile, Packet, PcapRecord, TrafficOverview } from '../../../../types/pcap'

export function usePcapWorkbench() {
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
  const filters = reactive({
    search: '', status: '', order_by: undefined as string | undefined, page: 1, page_size: 50,
  })
  // The capture list is paginated, so its sort is a server query; the packet and
  // file tables below are single-capture reads and sort client-side.
  const { onSortChange, orderBy } = useTableSort(() => { filters.page = 1; void load() })

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

  async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
    if (!silent) { loading.value = true; error.value = '' }
    try {
      filters.order_by = orderBy()
      const result = await listPcaps({ ...filters })
      items.value = result.items
      total.value = result.total
      error.value = ''
    } catch (err) {
      // Keep the last good list on a failed poll; a capture is not "gone"
      // because one request timed out.
      if (!silent) error.value = err instanceof Error ? err.message : String(err)
    } finally {
      if (!silent) loading.value = false
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
  const streamData = ref<TcpStreamFollow | null>(null)
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
  // Closing the preview dialog invalidates a byte fetch that is still in
  // flight, so a late answer cannot fill a dialog the operator already closed.
  function closeFileDialog(): void { ++fileVersion }

  // The capture list changes only when a segment arrives or an analysis
  // finishes, so a minute is enough; the task poller below has its own timer.
  useAutoRefresh(load, { intervalMs: 60000 })

  onMounted(load)
  onUnmounted(() => { ++viewVersion; ++packetVersion; ++detailVersion; ++fileVersion; ++taskVersion; clearTimeout(taskTimer) })

  return {
    evidenceDialog,
    alertEvidence,
    loading,
    error,
    items,
    total,
    selected,
    activeTab,
    flows,
    packets,
    alerts,
    dns,
    http,
    tls,
    files,
    traffic,
    protocolTree,
    applicationProtocols,
    anomalies,
    selectedPacket,
    packetDetail,
    packetDetailLoading,
    uploadProgress,
    packetQuery,
    packetTotal,
    flowTotal,
    packetLoading,
    packetError,
    fileNeedsAnalysis,
    fileCoverage,
    filePreview,
    fileDialog,
    fileLoading,
    fileError,
    activeFile,
    analyzingId,
    analysisStage,
    filters,
    onSortChange,
    packetLayers,
    packetHex,
    packetText,
    extractionLimited,
    selectedTcpStream,
    dnsColumns,
    httpColumns,
    tlsColumns,
    load,
    openPcap,
    runAnalyze,
    handleUpload,
    selectPacket,
    loadPackets,
    showFile,
    trackTask,
    streamDialog,
    streamData,
    streamLoading,
    followStream,
    reset,
    back,
    closeFileDialog,
  }
}
