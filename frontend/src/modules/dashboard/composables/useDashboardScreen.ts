/**
 * 数据安全态势大屏 state: the KPI band, the flow topology, the two donuts, the
 * switchable detection trend, the engine/probe cards and the live event list.
 *
 * Every series below is a projection of a server aggregate - the screen never
 * synthesises a number, and an empty list stays empty (an empty state is
 * information: it says the platform has nothing to report yet).
 *
 * The refresh timer belongs to this composable and is cleared on unmount; the
 * view keeps only routing, formatting and the node drawer.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import {
  getDashboardEngines, getDashboardOverview, getDetectionTrend, getGeoMap, getProbeStatus,
  getRecentAlerts, getRiskDistribution, getTrafficFlow,
} from '../../../api/dashboard'
import { listIntegrations } from '../../../api/integrations'
import type { Probe } from '../../../api/probes'
import type { Alert } from '../../../types/alert'
import type {
  DashboardOverview, DetectionTrendPoint, FlowLink, FlowNode, GeoDistribution, RiskDistribution,
  TrafficFlow,
} from '../../../types/dashboard'
import type { IntegrationStatus } from '../../../types/integration'
import { assetTypeLabels, severityLabels, severityOrder, severityTagColors } from '../../../utils/mapping'

/** Which series the 检测趋势 card shows. */
export type DetectionMetric = 'findings' | 'incidents' | 'alerts'

// The ``09-22`` axis label is shared with the cockpit, so it lives in
// utils/format; re-exported here for the callers (and tests) that read it from
// this module.
import { shortDay } from '../../../utils/format'

export { shortDay }

export interface DonutSlice {
  name: string
  value: number
  color?: string
}

/** How many links/nodes the topology may draw before it turns into hair. */
const TOPOLOGY_LIMIT = 18

const METRIC_LABELS: Record<DetectionMetric, string> = {
  findings: '检测发现',
  incidents: '安全事件',
  alerts: '安全告警',
}
const METRIC_COLORS: Record<DetectionMetric, string> = {
  findings: '#35a0ff',
  incidents: '#f5b638',
  alerts: '#ff4d5e',
}

/** Adapter name → the label the engine card shows. */
export const ENGINE_LABELS: Record<string, string> = {
  zeek: 'Zeek', suricata: 'Suricata', presidio: 'Presidio', misp: 'MISP',
  wazuh: 'Wazuh', sigma: 'Sigma', osquery: 'OsQuery', openscap: 'OpenSCAP',
}

/** The adapter's declared input types → one word the card can show. */
const CATEGORY_RULES: Array<[string, string[]]> = [
  ['流量分析', ['pcap', 'conn', 'flow', 'dns', 'http', 'tls', 'ssl', 'alert']],
  ['内容识别', ['text', 'file', 'fileinfo', 'regex-fallback', 'cn-pii']],
  ['情报匹配', ['ip', 'domain', 'hash', 'url', 'ioc-match']],
  ['主机审计', ['asset', 'process', 'user', 'config', 'log']],
  ['合规基线', ['cis', 'dengbao', 'xccdf', 'arf']],
]

export type EngineState = 'running' | 'error' | 'stopped'

export interface EngineRow {
  name: string
  label: string
  category: string
  state: EngineState
  stateLabel: string
  ruleCount: number | null
  findings: number
  version: string
}

/**
 * One adapter's health → the three states the card renders.
 *
 * A disabled adapter is 停止 (it is not running), an enabled but unhealthy one
 * is 异常 (it is supposed to run and cannot), and only enabled+healthy is 运行中.
 */
export function engineState(item: IntegrationStatus): EngineState {
  if (!item.enabled) return 'stopped'
  return item.healthy ? 'running' : 'error'
}

export function engineCategory(item: IntegrationStatus): string {
  const types = new Set([...(item.supported_types || []), ...(item.capabilities || [])])
  for (const [label, keys] of CATEGORY_RULES) {
    if (keys.some((key) => types.has(key))) return label
  }
  return '适配器'
}

/**
 * The four-level scale shared with the severity tags and the tables.
 *
 * Levels keep their colour whatever order the API returns them in, zero-valued
 * levels drop out, and a level the API reports that is not on the scale (say
 * ``Info``) still gets a slice instead of being silently swallowed.
 */
export function levelBreakdown(
  rows: Array<Record<string, unknown>>, key: string,
): DonutSlice[] {
  const counts = new Map(rows.map((row) => [String(row[key] ?? ''), Number(row.count ?? 0)]))
  const levels = [...severityOrder, ...counts.keys()].filter(
    (level, index, all) => all.indexOf(level) === index)
  return levels
    .map((level) => ({
      name: severityLabels[level] || level,
      value: counts.get(level) || 0,
      color: severityTagColors[level],
    }))
    .filter((entry) => entry.value > 0)
}

export function assetTypeBreakdown(
  rows: Array<{ type: string; count: number }>,
): DonutSlice[] {
  return [...rows]
    .filter((row) => Number(row.count) > 0)
    .sort((a, b) => Number(b.count) - Number(a.count))
    .map((row) => ({ name: assetTypeLabels[row.type] || row.type || '未分类', value: Number(row.count) }))
}

export interface UseDashboardScreenOptions {
  /** Milliseconds between refreshes; 0 disables the timer (used by the tests). */
  refreshMs?: number
  /** How many links the topology may draw. */
  topologyLimit?: number
}

export function useDashboardScreen(options: UseDashboardScreenOptions = {}) {
  const refreshMs = options.refreshMs ?? 30000
  const topologyLimit = options.topologyLimit ?? TOPOLOGY_LIMIT

  const loading = ref(true)
  const error = ref('')
  const overview = ref<DashboardOverview | null>(null)
  const traffic = ref<TrafficFlow | null>(null)
  const geo = ref<GeoDistribution | null>(null)
  const risk = ref<RiskDistribution | null>(null)
  const detectionTrend = ref<DetectionTrendPoint[]>([])
  const events = ref<Alert[]>([])
  const probes = ref<Probe[]>([])
  const integrations = ref<IntegrationStatus[]>([])
  const engineFindings = ref<Array<{ engine: string; count: number }>>([])
  const metric = ref<DetectionMetric>('findings')
  const updatedAt = ref<Date | null>(null)
  const now = ref(new Date())

  const riskSlices = computed(() => levelBreakdown(risk.value?.risk_levels || [], 'level'))
  const assetSlices = computed(() => assetTypeBreakdown(risk.value?.asset_types || []))
  const nodes = computed<FlowNode[]>(() => traffic.value?.nodes || [])
  const links = computed<FlowLink[]>(() => traffic.value?.links || [])
  const loop = computed(() => overview.value?.loop || null)
  // The detection window arrives as full ISO days; the card's axis has room
  // for MM-DD only, and the flow trend beside it already reads that way.
  const detectionX = computed(() => detectionTrend.value.map((item) => shortDay(item.time)))
  const detectionValues = computed(() =>
    detectionTrend.value.map((item) => Number(item[metric.value] || 0)))
  const detectionLabel = computed(() => METRIC_LABELS[metric.value])
  const detectionColor = computed(() => METRIC_COLORS[metric.value])
  const flowX = computed(() => (traffic.value?.trend || []).map((item) => item.time))

  const engineRows = computed<EngineRow[]>(() => {
    const findings = new Map(engineFindings.value.map((item) => [item.engine, item.count]))
    return [...integrations.value]
      .map((item) => {
        const state = engineState(item)
        return {
          name: item.name,
          label: ENGINE_LABELS[item.name] || item.name,
          category: engineCategory(item),
          state,
          stateLabel: state === 'running' ? '运行中' : state === 'error' ? '异常' : '已停止',
          ruleCount: item.rule_count ?? null,
          findings: findings.get(item.name) || 0,
          version: item.runtime_version || item.version || '',
        }
      })
      .sort((a, b) => Number(a.state !== 'running') - Number(b.state !== 'running')
        || b.findings - a.findings)
  })

  const engineSummary = computed(() => ({
    total: engineRows.value.length,
    running: engineRows.value.filter((row) => row.state === 'running').length,
    error: engineRows.value.filter((row) => row.state === 'error').length,
    stopped: engineRows.value.filter((row) => row.state === 'stopped').length,
  }))

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [
        overviewResult, trafficResult, geoResult, riskResult, trendResult,
        eventResult, probeResult, integrationResult, engineResult,
      ] = await Promise.all([
        getDashboardOverview(),
        getTrafficFlow({ limit: topologyLimit, days: 7 }),
        getGeoMap(),
        getRiskDistribution(),
        getDetectionTrend('7d'),
        getRecentAlerts(20),
        getProbeStatus(),
        listIntegrations(),
        getDashboardEngines(),
      ])
      overview.value = overviewResult
      traffic.value = trafficResult
      geo.value = geoResult
      risk.value = riskResult
      detectionTrend.value = trendResult.items
      events.value = eventResult
      probes.value = probeResult.items
      integrations.value = integrationResult
      engineFindings.value = engineResult.items
      updatedAt.value = new Date()
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  /** Reload without flashing the loading state — the wall keeps its numbers. */
  async function refresh(): Promise<void> {
    if (loading.value) return
    await load()
  }

  let timer = 0
  let clock = 0

  onMounted(() => {
    load()
    clock = window.setInterval(() => { now.value = new Date() }, 1000)
    if (refreshMs > 0) timer = window.setInterval(refresh, refreshMs)
  })

  onBeforeUnmount(() => {
    window.clearInterval(timer)
    window.clearInterval(clock)
  })

  return {
    loading, error, overview, traffic, geo, risk, detectionTrend, events, probes, integrations,
    engineFindings, metric, updatedAt, now,
    riskSlices, assetSlices, nodes, links, loop,
    detectionX, detectionValues, detectionLabel, detectionColor, flowX,
    engineRows, engineSummary,
    load, refresh,
  }
}
