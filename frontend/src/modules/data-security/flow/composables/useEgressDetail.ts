/**
 * 数据出境报告 state: the verdict per destination, and the drill-down that makes
 * a row actionable.
 *
 * A row on its own says "traffic left for this IP". The operator needs the
 * concrete flow, the capture it came from, whether the content was sensitive,
 * which rule caught it, and the parsed packets behind it — so this composable
 * owns all of that, including the packet paging of the selected flow.
 */
import { computed, onMounted, ref } from 'vue'
import { getAssessment, type AssessmentEnvelope } from '../../../../api/assessments'
import { useAutoRefresh } from '../../../../composables/useAutoRefresh'
import { useTableSort, sortRows } from '../../../../composables/useTableSort'
import { getPcapFlowPackets, getPcapPacketDetail } from '../../../../api/pcaps'
import type { Packet } from '../../../../types/pcap'

export interface EgressMatch {
  kind: string
  count: number
  sensitive: boolean
  confidence?: number | null
  rule_id: string
  rule_ids: string[]
  rule_source: string
  samples: Array<{ value: string; context: string }>
}

export interface EgressTransfer {
  pcap_id: number | null
  task_id: number
  object_id: number
  filename: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  size: number
  sha256: string
  complete: boolean
  content_type: string
  binary_available: boolean
  bucket: string
  region: string
  reason: string
  sensitive: boolean
  matches: EgressMatch[]
  rule_ids: string[]
  hit_count: number
  files: Array<{ instance_id: number; path: string; name: string; host: string; sensitivity: string }>
  file_bound: boolean
}

type Row = Record<string, unknown>

export function useEgressDetail() {
  const loading = ref(true)
  const error = ref('')
  const data = ref<AssessmentEnvelope | null>(null)
  const selected = ref<EgressTransfer | null>(null)
  const drawer = ref(false)
  const packets = ref<Packet[]>([])
  const packetTotal = ref(0)
  const packetsLoading = ref(false)
  const packetsNote = ref('')
  const detail = ref<Awaited<ReturnType<typeof getPcapPacketDetail>> | null>(null)
  /** Guards against a slow response from a previously opened row. */
  let request = 0

  const transfers = computed<EgressTransfer[]>(
    () => (data.value?.sections?.transfers as unknown as EgressTransfer[]) || [])
  const buckets = computed(() => (data.value?.sections?.buckets as Record<string, number>) || null)
  const regions = computed<Row[]>(() => (data.value?.sections?.regions as Row[]) || [])
  const rules = computed<Row[]>(() => (data.value?.sections?.rules as Row[]) || [])
  const policy = computed(() => (data.value?.sections?.policy as Row) || {})
  const sensitiveCount = computed(() => transfers.value.filter((row) => row.sensitive).length)

  // The report covers every captured object, so filtering and sorting stay in
  // the browser; the server sends the whole assessment envelope.
  const filters = ref({ search: '', sensitive_only: false, outgoing_only: false })
  const { sort, onSortChange } = useTableSort()
  const visibleTransfers = computed(() => {
    const needle = filters.value.search.trim().toLowerCase()
    const rows = transfers.value.filter((row) => {
      if (filters.value.sensitive_only && !row.sensitive) return false
      if (filters.value.outgoing_only && !['country', 'blacklist'].includes(row.bucket)) return false
      if (!needle) return true
      return [row.filename, row.src_ip, row.dst_ip, row.content_type, row.region]
        .some((field) => String(field || '').toLowerCase().includes(needle))
    })
    return sortRows(rows, sort.prop, sort.order, (row, prop) => (row as unknown as Record<string, unknown>)[prop])
  })

  async function load({ silent = false }: { silent?: boolean } = {}): Promise<void> {
    if (!silent) { loading.value = true; error.value = '' }
    try {
      data.value = await getAssessment('egress')
      error.value = ''
    } catch (err) {
      if (!silent) error.value = String(err)
    } finally {
      if (!silent) loading.value = false
    }
  }

  // An egress verdict only changes when a capture segment finishes analysis.
  useAutoRefresh(load, { intervalMs: 60000 })

  /** Every matched value of a transfer, flattened for the drawer table. */
  function matchedValues(row: EgressTransfer) {
    return (row.matches || []).flatMap((hit) => (hit.samples || []).map((sample) => ({
      kind: hit.kind,
      count: hit.count,
      ruleId: hit.rule_id || (hit.rule_ids || []).join(', '),
      source: hit.rule_source,
      value: sample.value,
      context: sample.context || '',
    })))
  }

  async function open(row: EgressTransfer): Promise<void> {
    selected.value = row
    drawer.value = true
    detail.value = null
    await loadPackets(1)
  }

  async function loadPackets(page: number): Promise<void> {
    const row = selected.value
    if (!row?.pcap_id) {
      packets.value = []
      packetTotal.value = 0
      packetsNote.value = '该对象没有关联抓包（历史数据），无法查看报文。'
      return
    }
    const token = ++request
    packetsLoading.value = true
    try {
      const result = await getPcapFlowPackets(row.pcap_id, {
        ip: row.dst_ip, port: row.dst_port, page, page_size: 200,
      })
      if (token !== request) return
      // The capture is indexed per port, so narrow to the exact conversation
      // rather than showing every flow that happens to reach the same service.
      const exact = result.items.filter((item) =>
        (item.src_ip === row.src_ip && item.src_port === row.src_port
          && item.dst_ip === row.dst_ip && item.dst_port === row.dst_port)
        || (item.src_ip === row.dst_ip && item.src_port === row.dst_port
          && item.dst_ip === row.src_ip && item.dst_port === row.src_port))
      packets.value = exact
      packetTotal.value = exact.length
      packetsNote.value = exact.length
        ? `抓包 #${row.pcap_id} 中该会话的报文（第 ${page} 页，按端口 ${row.dst_port} 检索后精确匹配）`
        : `抓包 #${row.pcap_id} 未索引到该会话的报文（可能只保留了协议解析结果）`
    } catch (err) {
      if (token !== request) return
      packets.value = []
      packetsNote.value = `读取报文失败：${String(err)}`
    } finally {
      if (token === request) packetsLoading.value = false
    }
  }

  async function openPacket(packet: Packet): Promise<void> {
    const row = selected.value
    if (!row?.pcap_id) return
    try {
      detail.value = await getPcapPacketDetail(row.pcap_id, packet.id)
    } catch (err) {
      packetsNote.value = `解析报文失败：${String(err)}`
    }
  }

  onMounted(load)

  return {
    loading, error, data, transfers, visibleTransfers, filters, sort, onSortChange,
    buckets, regions, rules, policy, sensitiveCount,
    selected, drawer, packets, packetTotal, packetsLoading, packetsNote, detail,
    load, open, loadPackets, openPacket, matchedValues,
  }
}
