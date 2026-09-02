<script setup lang="ts">
import { ref } from 'vue'
import { apiGet } from '../api/client'
import SeverityBadge from '../components/SeverityBadge.vue'
import RiskScore from '../components/RiskScore.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { useEcharts } from '../composables/useEcharts'

interface RiskSummary { count: number; risk_levels: Record<string, number>; engines: Record<string, number>; asset_risk: Record<string, number>; data_sensitivity: Record<string, number>; max_score: number; avg_score: number }
interface EngineInfo { name: string; version: string }
interface RiskItem { id: number; rule_id: string; engine: string; severity: string; risk_score: number }

const loading = ref(true)
const error = ref('')
const summary = ref<RiskSummary>({ count: 0, risk_levels: {}, engines: {}, asset_risk: {}, data_sensitivity: {}, max_score: 0, avg_score: 0 })
const engines = ref<EngineInfo[]>([])
const topFindings = ref<RiskItem[]>([])
const topIncidents = ref<RiskItem[]>([])
const riskEl = ref<HTMLElement | null>(null)
const severityEl = ref<HTMLElement | null>(null)
const gauge = useEcharts(riskEl)
const severity = useEcharts(severityEl)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [risk, registry, findings, incidents] = await Promise.all([
      apiGet<RiskSummary>('/risk/summary'),
      apiGet<EngineInfo[]>('/engine/registry'),
      apiGet<{ items: RiskItem[] }>('/detections', { page: 1, page_size: 10 }),
      apiGet<{ items: RiskItem[] }>('/incidents', { page: 1, page_size: 10 }),
    ])
    summary.value = risk
    engines.value = registry
    topFindings.value = findings.items
    topIncidents.value = incidents.items
    const score = Number(risk.max_score || 0)
    gauge.setOption({
      series: [{ type: 'gauge', min: 0, max: 100, progress: { show: true }, detail: { formatter: '{value}' }, data: [{ value: score, name: 'Risk' }] }],
    })
    const levels = risk.risk_levels
    severity.setOption({
      tooltip: {},
      series: [{ type: 'pie', radius: '70%', data: Object.entries(levels).map(([name, value]) => ({ name, value })) }],
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

void load()
</script>

<template>
  <div class="page-card">
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <template v-else>
      <el-row :gutter="12">
        <el-col :span="8"><el-card shadow="never"><div ref="riskEl" class="chart" /></el-card></el-col>
        <el-col :span="8"><el-card shadow="never"><template #header>Severity Distribution</template><div ref="severityEl" class="chart" /></el-card></el-col>
        <el-col :span="8"><el-card shadow="never"><template #header>Engine Registry</template><el-table :data="engines" size="small"><el-table-column prop="name" label="Engine" /><el-table-column prop="version" label="Version" /></el-table></el-card></el-col>
      </el-row>
      <el-row :gutter="12" class="section">
        <el-col :span="12">
          <el-card shadow="never"><template #header>Top Risk Findings</template><EmptyState v-if="!topFindings.length" /><el-table v-else :data="topFindings" size="small"><el-table-column prop="rule_id" label="规则" /><el-table-column prop="engine" label="Engine" /><el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="String(row.severity)" /></template></el-table-column><el-table-column label="风险" width="100"><template #default="{ row }"><RiskScore :score="Number(row.risk_score)" /></template></el-table-column></el-table></el-card>
        </el-col>
        <el-col :span="12">
          <el-card shadow="never"><template #header>Top Risk Incidents</template><EmptyState v-if="!topIncidents.length" /><el-table v-else :data="topIncidents" size="small"><el-table-column prop="title" label="事件" /><el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="String(row.severity)" /></template></el-table-column><el-table-column label="风险" width="100"><template #default="{ row }"><RiskScore :score="Number(row.risk_score)" /></template></el-table-column></el-table></el-card>
        </el-col>
      </el-row>
    </template>
  </div>
</template>

<style scoped>
.chart { height: 260px; }
.section { margin-top: 12px; }
</style>
