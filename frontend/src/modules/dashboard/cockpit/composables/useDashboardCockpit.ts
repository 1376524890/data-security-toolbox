/**
 * 数据安全综合驾驶舱 state: the KPI band, the posture ring, the two distribution
 * rings, the compliance board, 本周重点关注, the pipeline, the flow card and 最近任务.
 *
 * Three reads feed the page - ``/dashboard/overview`` (the aggregate the wall
 * screen also uses, whose cockpit half is additive), ``/dashboard/trend`` and
 * ``/dashboard/tasks``. Every number below is a projection of one of those
 * responses: the page never computes a score, never invents a category and never
 * fills a gap with a zero that would read as a measurement.
 *
 * The refresh timer belongs to this composable and is cleared on unmount; the
 * view keeps only layout, routing and formatting.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { getCockpitOverview, getCockpitTasks, getCockpitTrend } from '../../../../api/dashboard'
import type { Task } from '../../../../types/task'
import type {
  CockpitOverview, CockpitTrendPoint, ComplianceBoard, FocusRow,
  HealthScore, StatusRow, WeekWindow,
} from '../../../../types/dashboard'
import { formatDateTime, shortDay } from '../../../../utils/format'
import { assetTypeLabels, severityLabels, severityOrder, severityTagColors } from '../../../../utils/mapping'
import { cockpitColors, donutPalette } from '../chartTheme'

export { shortDay }
export type { CockpitTrendPoint }

/** The trend card's window; the flow bars and the KPI sparkline share it. */
export type CockpitRange = '7d' | '24h'

export interface DonutSlice { name: string; value: number; color: string }

export interface DistributionTab {
  key: string
  label: string
  total: number
  totalLabel: string
  slices: DonutSlice[]
}

/** One KPI card: the live count, its week window and where a click goes. */
export interface CockpitMetric {
  key: string
  label: string
  value: number
  unit: string
  delta_pct: number | null
  color: string
  icon: string
  hint: string
  /** ``false`` for a count that is good news when it grows (assets, coverage). */
  riseIsBad: boolean
  route: string
}

export interface FocusItem extends FocusRow { color: string; icon: string; route: string }

export interface PipelineStep {
  key: string
  label: string
  caption: string
  value: number
  icon: string
  color: string
  /** Empty for a stage the console has no page for (分析报告). */
  route: string
}

export interface TaskRow {
  id: number
  name: string
  kind_label: string
  status: string
  started_text: string
}

/** Task kind → the word the card shows. An unknown kind keeps its raw slug: a
 *  label invented here would be a claim about work the platform did not name. */
export const TASK_KIND_LABELS: Record<string, string> = {
  scan: '主动扫描',
  network_scan: '主动扫描',
  pcap: '流量解析',
  probe_scan: '探针扫描',
  data_asset_scan: '数据资产采集',
  database_scan: '数据库盘点',
  file_source_scan: '文件采集',
  monitoring: '持续监测',
}

/** Where each KPI card and focus row leads. The console has no separate
 *  事件/告警 pages - the risk list on 数据资产 is where both are acted on - so
 *  those rows open it rather than a route that would bounce back to "/". */
const ROUTES = {
  assets: '/data-assets',
  networkAssets: '/data-assets?view=network',
  findings: '/files',
  risk: '/data-assets',
  egress: '/network/dlp?view=egress',
} as const

/** 本周重点关注 row → colour, icon and destination. Keyed by the server's own
 *  row keys so a new row arrives with a destination instead of a dead link. */
const FOCUS_PRESENTATION: Record<string, { color: string; icon: string; route: string }> = {
  high_risk: { color: cockpitColors.red, icon: 'WarningFilled', route: ROUTES.findings },
  incidents: { color: cockpitColors.orange, icon: 'WarnTriangleFilled', route: ROUTES.risk },
  egress: { color: cockpitColors.violet, icon: 'Position', route: ROUTES.egress },
  alerts: { color: cockpitColors.amber, icon: 'Bell', route: ROUTES.risk },
  compliance: { color: cockpitColors.green, icon: 'CircleCheck', route: ROUTES.assets },
}

const REFRESH_MS = 30000

export function useDashboardCockpit(options: { refreshMs?: number } = {}) {
  const refreshMs = options.refreshMs ?? REFRESH_MS
  const loading = ref(false)
  const error = ref('')
  const overview = ref<CockpitOverview | null>(null)
  const trend = ref<CockpitTrendPoint[]>([])
  const tasks = ref<Task[]>([])
  const range = ref<CockpitRange>('7d')
  const updatedAt = ref<Date | null>(null)

  // Out-of-order responses: a refresh that started before a range switch must
  // not overwrite the newer window, so every response carries its ticket.
  let version = 0
  let timer = 0

  function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err || '加载失败')
  }

  async function refresh(): Promise<void> {
    const ticket = ++version
    loading.value = true
    try {
      const [nextOverview, nextTrend, nextTasks] = await Promise.all([
        getCockpitOverview(),
        getCockpitTrend(range.value),
        getCockpitTasks(8),
      ])
      if (ticket !== version) return
      overview.value = nextOverview
      trend.value = nextTrend.items
      tasks.value = nextTasks.items
      updatedAt.value = new Date()
      error.value = ''
    } catch (err) {
      if (ticket !== version) return
      // The last good numbers stay on screen: a blip must not blank a dashboard
      // that an operator is reading, so the failure is surfaced as a banner.
      error.value = message(err)
    } finally {
      if (ticket === version) loading.value = false
    }
  }

  function setRange(value: CockpitRange): void {
    if (range.value === value) return
    range.value = value
    void refresh()
  }

  onMounted(() => {
    void refresh()
    if (refreshMs > 0) timer = window.setInterval(() => { void refresh() }, refreshMs)
  })
  onBeforeUnmount(() => {
    // A landing timer would keep polling an unmounted page and, worse, would
    // write into a disposed component's refs.
    if (timer) window.clearInterval(timer)
    timer = 0
    version += 1
  })

  // ---------------------------------------------------------------------
  // Projections
  // ---------------------------------------------------------------------

  /** The week window for a KPI, or ``null`` when the server sent none.
   *  Named ``weekWindow`` on purpose: a local ``window`` would shadow the DOM
   *  global the refresh timer needs. */
  function weekWindow(key: keyof CockpitOverview['trends']): WeekWindow | null {
    return overview.value?.trends?.[key] ?? null
  }

  const metrics = computed<CockpitMetric[]>(() => {
    const data = overview.value
    if (!data) return []
    const specs: Array<Omit<CockpitMetric, 'value' | 'delta_pct'>> = [
      { key: 'asset_count', label: '资产总数', unit: '个', color: cockpitColors.blue,
        icon: 'Coin', hint: '平台已登记的主机与应用资产', riseIsBad: false, route: ROUTES.assets },
      { key: 'data_asset_count', label: '数据资产', unit: '个', color: cockpitColors.teal,
        icon: 'DataLine', hint: '已归并的数据对象（文件与数据库对象）', riseIsBad: false,
        route: ROUTES.assets },
      { key: 'network_asset_count', label: '网络资产', unit: '个', color: cockpitColors.cyan,
        icon: 'Connection', hint: '主动扫描发现的网络资产', riseIsBad: false,
        route: ROUTES.networkAssets },
      { key: 'finding_count', label: '发现项', unit: '项', color: cockpitColors.violet,
        icon: 'Search', hint: '检测引擎产出的全部发现', riseIsBad: true, route: ROUTES.findings },
      { key: 'incident_count', label: '安全事件', unit: '条', color: cockpitColors.red,
        icon: 'WarningFilled', hint: '由多个发现关联出的事件', riseIsBad: true, route: ROUTES.risk },
      { key: 'alert_count', label: '告警', unit: '条', color: cockpitColors.orange,
        icon: 'Bell', hint: '已投递的安全告警', riseIsBad: true, route: ROUTES.risk },
      { key: 'high_risk_count', label: '高风险项', unit: '项', color: cockpitColors.red,
        icon: 'WarnTriangleFilled', hint: '严重与高危级别的发现', riseIsBad: true,
        route: ROUTES.findings },
      { key: 'egress_event_count', label: '数据外发事件', unit: '个', color: cockpitColors.sky,
        icon: 'Position', hint: '去向已判定为外部地址的会话', riseIsBad: true, route: ROUTES.egress },
    ]
    return specs.map((spec) => ({
      ...spec,
      value: Number(data[spec.key as keyof CockpitOverview] || 0),
      delta_pct: weekWindow(spec.key as keyof CockpitOverview['trends'])?.delta_pct ?? null,
    }))
  })

  const health = computed<HealthScore | null>(() => overview.value?.health_score ?? null)

  const healthNote = computed(() => {
    const score = health.value?.score
    const components = health.value?.components || []
    const weakest = components
      .filter((item) => item.score !== null)
      .sort((a, b) => (a.score as number) - (b.score as number))[0]
    if (score === null || score === undefined) {
      return '暂无足够数据计算健康度：需要先有资产、数据对象与告警记录。'
    }
    const base = `当前数据安全健康度 ${score.toFixed(1)} 分`
    return weakest ? `${base}，四项指标中「${weakest.label}」最低（${weakest.score}），建议优先处理。` : base
  })

  const focus = computed<FocusItem[]>(() =>
    (overview.value?.focus || []).map((row) => ({
      ...row,
      color: FOCUS_PRESENTATION[row.key]?.color || cockpitColors.slate,
      icon: FOCUS_PRESENTATION[row.key]?.icon || 'InfoFilled',
      route: FOCUS_PRESENTATION[row.key]?.route || ROUTES.assets,
    })))

  const status = computed<StatusRow[]>(() => overview.value?.status || [])

  const compliance = computed<ComplianceBoard | null>(() => overview.value?.compliance_progress ?? null)

  /** 风险等级分布: the four severities in the console's fixed scale, in order. */
  const riskSlices = computed<DonutSlice[]>(() => {
    const rows = overview.value?.risk_distribution?.risk_levels || []
    const byLevel = new Map(rows.map((row) => [row.name, row.count]))
    return severityOrder
      .map((level) => ({
        name: severityLabels[level] || level,
        value: Number(byLevel.get(level) || 0),
        color: severityTagColors[level],
      }))
      .filter((slice) => slice.value > 0)
      .concat(
        // A level the scale does not know (an engine writing its own value) is
        // still a real finding, so it is drawn after the four, never dropped.
        rows.filter((row) => !severityOrder.includes(row.name as never))
          .map((row) => ({ name: row.name, value: row.count, color: cockpitColors.slate })),
      )
  })

  const riskTotal = computed(() => Number(overview.value?.risk_distribution?.total_findings || 0))

  /** 资产分布: the three inventories the server groups, as tabs. */
  const assetTabs = computed<DistributionTab[]>(() => {
    const data = overview.value
    if (!data) return []
    const paint = (rows: Array<{ name: string; count: number }>, label?: (name: string) => string) =>
      rows.filter((row) => row.count > 0).map((row, index) => ({
        name: label ? label(row.name) : (assetTypeLabels[row.name] || row.name),
        value: row.count,
        color: donutPalette[index % donutPalette.length],
      }))
    return [
      {
        key: 'asset_types', label: '资产类型', totalLabel: '资产总数',
        total: Number(data.asset_distribution?.total_assets || 0),
        slices: paint(data.asset_distribution?.asset_types || []),
      },
      {
        // 数据资产分级, not 分类: the platform stores a per-object sensitivity
        // level and a list of detector slugs - there is no 个人信息/业务数据
        // taxonomy table to group by, so the tab shows the ranking it has rather
        // than a category axis invented from detector names.
        key: 'data_sensitivity', label: '数据资产分级', totalLabel: '数据资产',
        total: Number(data.data_asset_count || 0),
        slices: paint(data.risk_distribution?.data_sensitivity || [],
                      (name) => severityLabels[name] || name),
      },
      {
        key: 'network_types', label: '网络资产类型', totalLabel: '网络资产',
        total: Number(data.asset_distribution?.total_network_assets || 0),
        slices: paint(data.asset_distribution?.network_types || []),
      },
    ]
  })

  const pipeline = computed<PipelineStep[]>(() => {
    const loop = overview.value?.loop
    if (!loop) return []
    return [
      { key: 'assets', label: '资产发现', caption: '资产总数', value: loop.assets,
        icon: 'Coin', color: cockpitColors.blue, route: ROUTES.assets },
      { key: 'findings', label: '安全发现', caption: '发现项', value: loop.findings,
        icon: 'Search', color: cockpitColors.violet, route: ROUTES.findings },
      { key: 'incidents', label: '安全事件', caption: '安全事件', value: loop.incidents,
        icon: 'WarningFilled', color: cockpitColors.orange, route: ROUTES.risk },
      { key: 'alerts', label: '告警处置', caption: '告警数量', value: loop.alerts,
        icon: 'Bell', color: cockpitColors.red, route: ROUTES.risk },
      // 分析报告 has no console page in this build, so the node is drawn but not
      // clickable rather than linking somewhere that only looks like a report.
      { key: 'reports', label: '分析报告', caption: '报告总数', value: loop.reports,
        icon: 'Document', color: cockpitColors.green, route: '' },
    ]
  })

  /** The task card's rows: a real name from the payload when the task has one. */
  const taskRows = computed<TaskRow[]>(() => tasks.value.map((row) => {
    const payload = (row.payload || {}) as Record<string, unknown>
    const config = (payload.config || {}) as Record<string, unknown>
    const kindLabel = TASK_KIND_LABELS[row.kind] || row.kind
    const named = typeof config.name === 'string' && config.name ? config.name : ''
    const target = typeof payload.target === 'string' && payload.target ? payload.target : ''
    const probe = payload.probe_id ? `探针 #${payload.probe_id}` : ''
    return {
      id: row.id,
      name: named || [kindLabel, target || probe].filter(Boolean).join(' ') || `任务 #${row.id}`,
      kind_label: kindLabel,
      status: row.status,
      started_text: formatDateTime(row.started_at || row.created_at),
    }
  }))

  const flowTotals = computed(() => overview.value?.flow?.totals ?? null)
  const flowWeekly = computed(() => overview.value?.flow?.weekly ?? null)

  return {
    loading, error, overview, trend, tasks, range, updatedAt,
    refresh, setRange,
    metrics, health, healthNote, focus, status, compliance,
    riskSlices, riskTotal, assetTabs, pipeline, taskRows,
    flowTotals, flowWeekly,
    stale: computed(() => Boolean(overview.value && error.value)),
  }
}
