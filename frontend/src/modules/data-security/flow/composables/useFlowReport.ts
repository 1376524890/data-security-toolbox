/**
 * The risk-flow report state: the transfers the platform captured, the sensitive
 * content found in them, and the single on/off switch for the rule set.

 * There is deliberately no rule editor here — rules are configured in 采集与规则.
 * This page only runs the check and shows what it found.
 */
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { apiGet, apiPost } from '../../../../api/client'

export interface MatchedText { value: string; context?: string }
export interface FlowHit {
  kind: string; count: number; confidence?: number; sensitive?: boolean
  rule_id?: string; rule_ids?: string[]; rule_source?: string; rule_sources?: string[]
  matches?: MatchedText[]
}
export interface Transfer {
  task_id: number; id: number; pcap_id: number; filename: string
  src_ip: string; src_port: number; dst_ip: string; dst_port: number
  size: number; sha256: string; complete: boolean; content_type: string
  binary_available?: boolean; matches: FlowHit[]
}

export function useFlowReport() {
  const loading = ref(true)
  const error = ref('')
  const transfers = ref<Transfer[]>([])
  const coverage = ref<unknown[]>([])
  const enabled = ref(false)
  const threshold = ref(0.6)
  const busy = ref(false)
  const selected = ref<Transfer | null>(null)
  const drawer = ref(false)
  const binary = ref('')
  const binaryError = ref('')
  const binaryLoading = ref(false)
  let evidenceRequest = 0

  /** Every matched原文 across a transfer, flattened for the evidence drawer. */
  function matchedText(row: Transfer) {
    return (row.matches || []).flatMap((hit) => (hit.matches || []).map((match) => ({
      kind: hit.kind, count: hit.count,
      ruleId: hit.rule_id || (hit.rule_ids || []).join(', '),
      source: hit.rule_source || (hit.rule_sources || []).join(', '),
      value: match.value, context: match.context || '',
    })))
  }
  function alertable(hit: FlowHit): boolean {
    return hit.sensitive !== false && (hit.confidence ?? 1) >= threshold.value
  }
  const riskyCount = computed(() => transfers.value.filter((row) => row.matches.some(alertable)).length)

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [policy, data] = await Promise.all([
        apiGet<{ enabled: boolean; min_confidence: number }>('/dlp/policy'),
        apiGet<{ items: Transfer[]; coverage: unknown[] }>('/dlp/transfers'),
      ])
      enabled.value = Boolean(policy.enabled)
      threshold.value = Number(policy.min_confidence ?? 0.6)
      transfers.value = data.items
      coverage.value = data.coverage
    } catch (err) {
      error.value = String(err)
    } finally {
      loading.value = false
    }
  }

  async function toggleRuleSet(value: boolean): Promise<void> {
    busy.value = true
    try {
      await apiPost('/dlp/policy', { enabled: value })
      enabled.value = value
      ElMessage.success(value ? '规则集已启用，对后续分析生效' : '规则集已停用')
    } catch (err) {
      enabled.value = !value
      ElMessage.error(String(err))
    } finally {
      busy.value = false
    }
  }

  async function openTransfer(row: Transfer): Promise<void> {
    selected.value = row
    drawer.value = true
    binary.value = ''
    binaryError.value = ''
    const request = ++evidenceRequest
    binaryLoading.value = false
    if (!row.binary_available) return
    binaryLoading.value = true
    try {
      const data = await apiGet<{ hex: string }>(`/dlp/transfers/${row.task_id}/${row.id}/content`)
      if (request === evidenceRequest) binary.value = data.hex
    } catch (err) {
      if (request === evidenceRequest) binaryError.value = String(err)
    } finally {
      if (request === evidenceRequest) binaryLoading.value = false
    }
  }

  onMounted(load)
  return { loading, error, transfers, coverage, enabled, threshold, busy, selected, drawer,
    binary, binaryError, binaryLoading, riskyCount, matchedText, alertable, load, toggleRuleSet,
    openTransfer }
}
