<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { getDashboardSummary, getRiskTrend, getIncidentTrend, getDashboardSeverity, getDashboardEngines, getDashboardIncidents, getHighRiskAssets, getSensitiveData } from '../../api/dashboard'
import { getRiskSummary, type RiskSummary } from '../../api/risk'
import { getHealth, type HealthResponse } from '../../api/health'
import type { DashboardSummary } from '../../types/dashboard'
import type { Incident } from '../../types/incident'
import type { Asset } from '../../types/asset'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import TrendChart from '../../components/charts/TrendChart.vue'
import DonutChart from '../../components/charts/DonutChart.vue'
import BarChart from '../../components/charts/BarChart.vue'
import GaugeChart from '../../components/charts/GaugeChart.vue'
import { formatDateTime } from '../../utils/format'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const summary = ref<DashboardSummary | null>(null)
const risk = ref<RiskSummary | null>(null)
const health = ref<HealthResponse | null>(null)
const incidents = ref<Incident[]>([])
const assets = ref<Asset[]>([])
const trend = ref<{ time: string; count: number; risk_score: number }[]>([])
const incidentTrend = ref<Array<{ time: string; count: number }>>([])

const riskLevels = computed(() => {
  const levels = risk.value?.risk_levels || {}
  return ['Critical', 'High', 'Medium', 'Low'].map((level) => ({ level, count: levels[level] || 0 }))
})

const severityData = ref<Array<{ name: string; value: number }>>([])
const engineData = ref<{ x: string[]; y: number[] }>({ x: [], y: [] })
const sensitiveData = ref<Array<{ name: string; value: number }>>([])

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
    summary.value = s
    risk.value = r
    health.value = h
    incidents.value = inc.items
    assets.value = asset.items
    trend.value = trendResult.items
    incidentTrend.value = incidentTrendResult.items
    severityData.value = sev.items.map((i) => ({ name: i.severity, value: i.count }))
    engineData.value = { x: eng.items.map((i) => i.engine), y: eng.items.map((i) => i.count) }
    sensitiveData.value = sensitive.items.map((i) => ({ name: i.category, value: i.count }))
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <StateBox :loading="loading" :error="error" :empty="!summary" @retry="load">
      <template v-if="summary && risk">
        <!-- Security metrics -->
        <div class="stat-grid cols-6">
          <StatCard label="告警" :value="summary.alerts" :sub="`开放 ${summary.open_alerts}`" tone="danger" />
          <StatCard label="安全事件" :value="summary.incidents" :sub="`开放 ${summary.open_incidents}`" tone="warning" />
          <StatCard label="检测" :value="summary.high_risk_findings" sub="高危检测" tone="warning" />
          <StatCard label="高风险资产" :value="summary.high_risk_assets" tone="danger" />
          <StatCard label="敏感数据资产" :value="summary.sensitive_data_assets" tone="warning" />
          <StatCard label="在线探针" :value="summary.online_probes" tone="success" />
        </div>

        <!-- Risk distribution + run status -->
        <div class="grid cols-3" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />风险等级分布</div>
            <div class="risk-levels">
              <div v-for="item in riskLevels" :key="item.level" class="risk-level-row">
                <RiskBadge :level="item.level" />
                <span class="risk-count">{{ item.count }}</span>
                <el-progress :percentage="summary ? Math.round((item.count / Math.max(1, risk.count)) * 100) : 0" :show-text="false" :stroke-width="6" :color="item.level === 'Critical' ? '#ef4444' : item.level === 'High' ? '#f97316' : item.level === 'Medium' ? '#eab308' : '#3b82f6'" />
              </div>
            </div>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />运行状态</div>
            <div class="run-grid">
              <div class="run-item"><span class="run-label">探针</span><StatusBadge :value="(health?.probe?.online || 0) > 0 ? 'online' : 'offline'" /><span class="run-num">{{ health?.probe?.count || 0 }}</span></div>
              <div class="run-item"><span class="run-label">工作进程</span><StatusBadge :value="health?.analysis_worker || 'offline'" /></div>
              <div class="run-item"><span class="run-label">队列</span><StatusBadge :value="(health?.queue?.pending || 0) > 0 ? 'running' : 'ready'" /><span class="run-num">{{ health?.queue?.pending || 0 }} 待处理</span></div>
              <div class="run-item"><span class="run-label">集成组件</span><StatusBadge :value="(health?.analysis_worker === 'ready') ? 'ready' : 'disabled'" /><span class="run-num">{{ summary.healthy_integrations }}</span></div>
            </div>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />风险评分</div>
            <GaugeChart :value="risk.avg_score" :height="220" />
            <div class="gauge-meta">最高 {{ risk.max_score }} · 平均 {{ risk.avg_score }} · 共 {{ risk.count }}</div>
          </div>
        </div>

        <!-- Trends -->
        <div class="grid cols-2" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />风险 / 检测趋势 (近 7 天)</div>
            <TrendChart :x-data="trend.map((t) => t.time)" :series="[
              { name: '风险评分', data: trend.map((t) => t.risk_score), color: '#38bdf8', area: true },
              { name: '检测数', data: trend.map((t) => t.count), color: '#f97316' },
              { name: '安全事件', data: incidentTrend.map((t) => t.count), color: '#a855f7' },
            ]" :height="300" />
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />严重等级分布</div>
            <DonutChart :data="severityData" :height="300" />
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />引擎检测分布</div>
            <BarChart :x-data="engineData.x" :data="engineData.y" :height="300" />
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />敏感数据分布</div>
            <DonutChart :data="sensitiveData" :height="300" />
          </div>
        </div>

        <!-- Recent incidents & high-risk assets -->
        <div class="grid cols-2" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />最新安全事件</div>
            <el-table :data="incidents" size="small" @row-click="(row: Incident) => router.push('/incidents')">
              <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
              <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
              <el-table-column prop="title" label="标题" min-width="180" show-overflow-tooltip />
              <el-table-column prop="risk_score" label="风险" width="80" />
            </el-table>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />高风险资产</div>
            <el-table :data="assets" size="small" @row-click="(row: Asset) => router.push('/assets')">
              <el-table-column prop="ip" label="IP" />
              <el-table-column prop="service" label="服务" />
              <el-table-column prop="asset_type" label="类型" />
              <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :level="row.risk_level" /></template></el-table-column>
            </el-table>
          </div>
        </div>
      </template>
    </StateBox>
  </div>
</template>

<style scoped>
.risk-levels { display: flex; flex-direction: column; gap: 10px; }
.risk-level-row { display: grid; grid-template-columns: 80px 40px 1fr; align-items: center; gap: 10px; }
.risk-count { font-weight: 700; color: var(--soc-text); }
.run-grid { display: flex; flex-direction: column; gap: 10px; }
.run-item { display: flex; align-items: center; gap: 10px; justify-content: space-between; padding: 6px 0; border-bottom: 1px dashed var(--soc-border); }
.run-label { color: var(--soc-text-muted); }
.run-num { color: var(--soc-text-dim); font-size: 12px; }
.gauge-meta { color: var(--soc-text-dim); font-size: 12px; text-align: center; margin-top: 4px; }
</style>
