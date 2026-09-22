export interface DashboardSummary {
  assets: number
  files: number
  pcaps: number
  anomalies: number
  tasks: number
  reports: number
  probes: number
  incidents: number
  iocs: number
  alerts: number
  open_alerts: number
  high_risk_findings: number
  open_incidents: number
  high_risk_assets: number
  sensitive_data_assets: number
  online_probes: number
  healthy_integrations: number
}

export interface TrendPoint {
  time: string
  risk_score: number
  count: number
  critical: number
  high: number
}

export interface RiskTrendResponse {
  range: string
  items: TrendPoint[]
}

export interface NameCount {
  name: string
  value: number
}

export interface DashboardItems<T> {
  items: T[]
}

// ---------------------------------------------------------------------------
// 数据安全态势大屏 (big screen)
//
// Every shape below mirrors an aggregate the server derives from its own rows.
// Nothing here is a sample or a placeholder: if a field is empty on the screen
// it is empty in the database.
// ---------------------------------------------------------------------------

/** Total plus today/yesterday counts; ``delta_pct`` is null when yesterday had none. */
export interface MetricWindow {
  total: number
  today: number
  yesterday: number
  delta_pct: number | null
}

export interface DashboardOverview {
  generated_at: string
  alerts: MetricWindow & { open: number; critical_high: number }
  incidents: MetricWindow & { open: number }
  findings: MetricWindow & { high_risk: number }
  assets: { total: number; high_risk: number; sensitive: number; data_assets: number }
  /** 资产发现 → 检测发现 → 安全事件 → 告警处置 → 分析报告 */
  loop: { assets: number; findings: number; incidents: number; alerts: number; reports: number }
  probes: { total: number; online: number; degraded: number; offline: number }
  integrations: { total: number; healthy: number }
}

/** The three classes the egress classifier can prove; there is no "跨域" bucket. */
export type FlowDirection = 'internal' | 'external' | 'unknown'

export interface FlowNode {
  id: string
  ip: string
  name: string
  kind: 'asset' | 'host' | 'external'
  bucket: string
  asset_id: number | null
  hostname: string
  os: string
  port: number
  service: string
  asset_type: string
  risk_level: string
  sensitive_categories: string[]
  sessions: number
  bytes: number
  packets: number
  external_sessions: number
  data_assets: number
  findings: number
  high_risk_findings: number
  incidents: number
}

export interface FlowLink {
  source: string
  target: string
  src_ip: string
  dst_ip: string
  sessions: number
  bytes: number
  packets: number
  direction: FlowDirection
  bucket: string
}

export interface FlowTrendPoint {
  time: string
  internal: number
  external: number
  unknown: number
}

export interface TrafficFlow {
  generated_at: string
  days: number
  totals: {
    sessions: number
    bytes: number
    packets: number
    internal: number
    external: number
    unknown: number
    bytes_by_direction: Record<FlowDirection, number>
  }
  nodes: FlowNode[]
  links: FlowLink[]
  trend: FlowTrendPoint[]
}

export interface RiskDistribution {
  risk_levels: Array<{ level: string; count: number }>
  severity: Array<{ severity: string; count: number }>
  asset_types: Array<{ type: string; count: number }>
  sensitivity: Array<{ sensitivity: string; count: number }>
  total_findings: number
  total_assets: number
}

export interface DetectionTrendPoint {
  time: string
  findings: number
  incidents: number
  alerts: number
}

// ---------------------------------------------------------------------------
// 数据安全综合驾驶舱 (console cockpit)
//
// The daily-use homepage reads `GET /dashboard/overview` — the same aggregate
// the 态势大屏 reads — plus `/dashboard/trend` and `/dashboard/tasks`. Every
// number below is derived by the server from stored rows; a dimension with no
// denominator arrives as `null` so the page can print "—" instead of a zero
// that would read as a failure.
// ---------------------------------------------------------------------------

/** One KPI's week window: the last 7 days against the 7 before them. */
export interface WeekWindow {
  week: number
  prev_week: number
  /** ``null`` when the previous week had no rows (a % against 0 would lie). */
  delta_pct: number | null
}

/** A ``{name, count}`` row from a server-side group-by. */
export interface CockpitCount {
  name: string
  count: number
}

/** One sub-score of the posture ring, with the arithmetic that produced it. */
export interface HealthComponent {
  key: string
  label: string
  score: number | null
  /** ``null`` for 合规管理, which averages four rates and has no single pair. */
  numerator: number | null
  denominator: number | null
  detail: string
}

export interface HealthScore {
  score: number | null
  grade: string
  components: HealthComponent[]
  /** The weights actually applied (a dimension without data is left out). */
  weights: Record<string, number>
}

export interface ComplianceCheck {
  key: string
  label: string
  numerator: number
  denominator: number
  rate: number | null
  detail: string
}

export interface ComplianceBoard {
  rate: number | null
  passed: number
  measured: number
  checks: ComplianceCheck[]
}

/** 本周重点关注: one actionable row, already carrying its own trend. */
export interface FocusRow {
  key: string
  label: string
  value: number | null
  unit: string
  hint: string
  delta_pct: number | null
}

/** 探针与引擎状态: an up/total pair, never a bare percentage. */
export interface StatusRow {
  key: string
  label: string
  up: number
  total: number
  rate: number | null
  detail: string
}

export interface FlowDirectionTotals {
  sessions: number
  bytes: number
  destinations: number
}

/** The cockpit half of the overview, on top of the wall screen's blocks. */
export interface CockpitOverview extends DashboardOverview {
  asset_count: number
  data_asset_count: number
  network_asset_count: number
  finding_count: number
  incident_count: number
  alert_count: number
  high_risk_count: number
  egress_event_count: number
  health_score: HealthScore
  risk_distribution: {
    risk_levels: CockpitCount[]
    severity: Array<{ severity: string; count: number }>
    data_sensitivity: CockpitCount[]
    total_findings: number
  }
  asset_distribution: {
    asset_types: CockpitCount[]
    network_types: CockpitCount[]
    total_assets: number
    total_network_assets: number
  }
  compliance_progress: ComplianceBoard
  flow: {
    totals: Record<FlowDirection, FlowDirectionTotals>
    weekly: Record<FlowDirection, WeekWindow>
  }
  focus: FocusRow[]
  status: StatusRow[]
  trends: {
    asset_count: WeekWindow
    data_asset_count: WeekWindow
    network_asset_count: WeekWindow
    finding_count: WeekWindow
    incident_count: WeekWindow
    alert_count: WeekWindow
    high_risk_count: WeekWindow
    egress_event_count: WeekWindow
  }
}

/** One day of the cockpit's trend: detections plus the three flow classes. */
export interface CockpitTrendPoint {
  time: string
  findings: number
  incidents: number
  alerts: number
  internal: number
  external: number
  unknown: number
}

export interface CockpitTrend {
  range: string
  items: CockpitTrendPoint[]
}
