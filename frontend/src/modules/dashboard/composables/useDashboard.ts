/**
 * Dashboard state: the summary counters, the risk gauge, the runtime health,
 * the two trend series and the four chart series.
 *
 * Both donuts are the same four-level scale (finding severity, data-asset
 * sensitivity).  The levels are ordered Critical -> Low and coloured like the
 * severity tags, so a slice keeps its colour however the API orders the rows,
 * and the charts read the same as the tables beside them.
 */
import { computed, onMounted, ref } from 'vue'
import { getDashboardSummary, getRiskTrend, getIncidentTrend, getDashboardSeverity, getDashboardEngines, getDashboardIncidents, getHighRiskAssets, getSensitiveData } from '../../../api/dashboard'
import { getRiskSummary, type RiskSummary } from '../../../api/risk'
import { getHealth, type HealthResponse } from '../../../api/health'
import { getAssessment, type AssessmentEnvelope } from '../../../api/assessments'
import type { DashboardSummary } from '../../../types/dashboard'
import type { Incident } from '../../../types/incident'
import type { Asset } from '../../../types/asset'
import { severityLabels, severityOrder, severityTagColors } from '../../../utils/mapping'

export function useDashboard() {
  const loading = ref(true)
  const error = ref('')
  const summary = ref<DashboardSummary | null>(null)
  const risk = ref<RiskSummary | null>(null)
  const health = ref<HealthResponse | null>(null)
  const incidents = ref<Incident[]>([])
  const assets = ref<Asset[]>([])
  const trend = ref<{ time: string; count: number; risk_score: number }[]>([])
  const incidentTrend = ref<Array<{ time: string; count: number }>>([])
  // The data-security headline, taken from the same read-only assessment the
  // 数据资产 tab renders, so the big screen and the detail page never disagree.
  const assessment = ref<AssessmentEnvelope | null>(null)

  const riskLevels = computed(() => {
    const levels = risk.value?.risk_levels || {}
    return ['Critical', 'High', 'Medium', 'Low'].map((level) => ({ level, count: levels[level] || 0 }))
  })

  const severityData = ref<Array<{ name: string; value: number; itemStyle?: { color?: string } }>>([])
  const engineData = ref<{ x: string[]; y: number[] }>({ x: [], y: [] })
  const sensitiveData = ref<Array<{ name: string; value: number; itemStyle?: { color?: string } }>>([])

  // Both donuts are the same four-level scale (finding severity, data-asset
  // sensitivity). The levels are ordered Critical -> Low and coloured like the
  // severity tags, so a slice keeps its colour however the API orders the rows,
  // and the charts read the same as the tables beside them.
  function levelBreakdown(rows: Array<Record<string, unknown>>, key: string) {
    const counts = new Map(rows.map((row) => [String(row[key] ?? ''), Number(row.count ?? 0)]))
    const levels = [...severityOrder, ...counts.keys()].filter((level, index, all) => all.indexOf(level) === index)
    return levels
      .map((level) => ({
        name: severityLabels[level] || level,
        value: counts.get(level) || 0,
        itemStyle: { color: severityTagColors[level] },
      }))
      .filter((entry) => entry.value > 0)
  }

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [s, r, h, trendResult, incidentTrendResult, sev, eng, inc, asset, sensitive] = await Promise.all([
        getDashboardSummary(),
        getRiskSummary(),
        getHealth(),
        getRiskTrend('7d'),
        getIncidentTrend('7d'),
        getDashboardSeverity(),
        getDashboardEngines(),
        getDashboardIncidents(),
        getHighRiskAssets(),
        getSensitiveData(),
      ])
      getAssessment('overview').then((data) => { assessment.value = data }).catch(() => undefined)
      summary.value = s
      risk.value = r
      health.value = h
      incidents.value = inc.items
      assets.value = asset.items
      trend.value = trendResult.items
      incidentTrend.value = incidentTrendResult.items
      severityData.value = levelBreakdown(sev.items, 'severity')
      engineData.value = { x: eng.items.map((i) => i.engine), y: eng.items.map((i) => i.count) }
      sensitiveData.value = levelBreakdown(sensitive.items, 'category')
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      loading.value = false
    }
  }

  onMounted(load)

  return {
    loading, error, summary, risk, health, incidents, assets, trend, incidentTrend,
    riskLevels, severityData, engineData, sensitiveData, assessment, load,
  }
}
