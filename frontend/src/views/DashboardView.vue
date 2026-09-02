<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import StatCard from '../components/StatCard.vue'
import SeverityBadge from '../components/SeverityBadge.vue'
import RiskScore from '../components/RiskScore.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { getDashboardSummary, getRiskTrend, getDashboardSeverity, getDashboardEngines, getDashboardIncidents, getHighRiskAssets, getSensitiveData } from '../api/dashboard'
import type { DashboardSummary } from '../types/dashboard'
import type { Incident } from '../types/incident'
import type { Asset } from '../types/asset'
import { useEcharts } from '../composables/useEcharts'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const summary = ref<DashboardSummary | null>(null)
const incidents = ref<Incident[]>([])
const assets = ref<Asset[]>([])
const trendEl = ref<HTMLElement | null>(null)
const severityEl = ref<HTMLElement | null>(null)
const engineEl = ref<HTMLElement | null>(null)
const sensitiveEl = ref<HTMLElement | null>(null)
const trend = useEcharts(trendEl)
const severity = useEcharts(severityEl)
const engines = useEcharts(engineEl)
const sensitive = useEcharts(sensitiveEl)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [summaryResult, trendResult, severityResult, enginesResult, incidentResult, assetResult, sensitiveResult] = await Promise.all([
      getDashboardSummary(),
      getRiskTrend('7d'),
      getDashboardSeverity(),
      getDashboardEngines(),
      getDashboardIncidents(),
      getHighRiskAssets(),
      getSensitiveData(),
    ])
    summary.value = summaryResult
    incidents.value = incidentResult.items
    assets.value = assetResult.items
    trend.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 40, right: 20, top: 20, bottom: 30 },
      xAxis: { type: 'category', data: trendResult.items.map((item) => item.time) },
      yAxis: { type: 'value' },
      series: [
        { name: 'Risk Score', type: 'line', smooth: true, data: trendResult.items.map((item) => item.risk_score), areaStyle: {} },
        { name: 'Findings', type: 'line', smooth: true, data: trendResult.items.map((item) => item.count) },
      ],
    })
    severity.setOption({
      tooltip: { trigger: 'item' },
      series: [{ type: 'pie', radius: ['45%', '70%'], data: severityResult.items.map((item) => ({ name: item.severity, value: item.count })) }],
    })
    engines.setOption({
      tooltip: {},
      xAxis: { type: 'category', data: enginesResult.items.map((item) => item.engine), axisLabel: { rotate: 30 } },
      yAxis: { type: 'value' },
      series: [{ type: 'bar', data: enginesResult.items.map((item) => item.count) }],
    })
    sensitive.setOption({
      tooltip: { trigger: 'item' },
      series: [{ type: 'pie', radius: '65%', data: sensitiveResult.items.map((item) => ({ name: item.category, value: item.count })) }],
    })
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
    ElMessage.error(error.value)
  } finally {
    loading.value = false
  }
}

void load()
</script>

<template>
  <div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <template v-else-if="summary">
      <el-row :gutter="12">
        <el-col :span="4"><StatCard label="高危 Finding" :value="summary.high_risk_findings" tone="danger" /></el-col>
        <el-col :span="4"><StatCard label="Open Incident" :value="summary.open_incidents" tone="warning" /></el-col>
        <el-col :span="4"><StatCard label="总资产" :value="summary.assets" /></el-col>
        <el-col :span="4"><StatCard label="高风险资产" :value="summary.high_risk_assets" tone="danger" /></el-col>
        <el-col :span="4"><StatCard label="敏感数据资产" :value="summary.sensitive_data_assets" tone="warning" /></el-col>
        <el-col :span="4"><StatCard label="在线 Probe" :value="summary.online_probes" tone="info" /></el-col>
      </el-row>
      <el-row :gutter="12" class="section">
        <el-col :span="12"><el-card shadow="never"><template #header>风险趋势</template><div ref="trendEl" class="chart" /></el-card></el-col>
        <el-col :span="12"><el-card shadow="never"><template #header>Severity 分布</template><div ref="severityEl" class="chart" /></el-card></el-col>
        <el-col :span="12"><el-card shadow="never"><template #header>Engine Finding 分布</template><div ref="engineEl" class="chart" /></el-card></el-col>
        <el-col :span="12"><el-card shadow="never"><template #header>敏感数据分布</template><div ref="sensitiveEl" class="chart" /></el-card></el-col>
      </el-row>
      <el-row :gutter="12" class="section">
        <el-col :span="12">
          <el-card shadow="never">
            <template #header>最新安全事件</template>
            <EmptyState v-if="!incidents.length" />
            <el-table v-else :data="incidents" size="small">
              <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
              <el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column>
              <el-table-column prop="title" label="标题" />
              <el-table-column label="风险" width="80"><template #default="{ row }"><RiskScore :score="row.risk_score" /></template></el-table-column>
            </el-table>
          </el-card>
        </el-col>
        <el-col :span="12">
          <el-card shadow="never">
            <template #header>高风险资产</template>
            <EmptyState v-if="!assets.length" />
            <el-table v-else :data="assets" size="small">
              <el-table-column prop="ip" label="IP" />
              <el-table-column prop="service" label="服务" />
              <el-table-column prop="asset_type" label="类型" />
              <el-table-column label="风险" width="90"><template #default="{ row }"><SeverityBadge :value="row.risk_level" /></template></el-table-column>
            </el-table>
          </el-card>
        </el-col>
      </el-row>
    </template>
  </div>
</template>

<style scoped>
.section { margin-top: 12px; }
.chart { height: 300px; }
</style>
