<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { getRiskSummary, type RiskSummary } from '../../../api/risk'
import { getEngineRegistry, type EngineInfo } from '../../../api/engine'
import { listDetections } from '../../../api/detections'
import { listIncidents } from '../../../api/incidents'
import type { DetectionFinding } from '../../../types/finding'
import type { Incident } from '../../../types/incident'
import StateBox from '../../../components/common/StateBox.vue'
import StatCard from '../../../components/common/StatCard.vue'
import GaugeChart from '../../../components/charts/GaugeChart.vue'
import BarChart from '../../../components/charts/BarChart.vue'
import DonutChart from '../../../components/charts/DonutChart.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import RiskBadge from '../../../components/security/RiskBadge.vue'
import { formatDateTime } from '../../../utils/format'

const router = useRouter()
const loading = ref(true)
const error = ref('')
const summary = ref<RiskSummary | null>(null)
const engines = ref<EngineInfo[]>([])
const topFindings = ref<DetectionFinding[]>([])
const topIncidents = ref<Incident[]>([])

const assetRiskData = computed(() => Object.entries(summary.value?.asset_risk || {}).map(([name, value]) => ({ name, value })))
const dataSensitivityData = computed(() => Object.entries(summary.value?.data_sensitivity || {}).map(([name, value]) => ({ name, value })))
const engineData = computed(() => {
  const entries = Object.entries(summary.value?.engines || {})
  return { x: entries.map(([k]) => k), y: entries.map(([, v]) => v) }
})

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [risk, registry, findings, incidents] = await Promise.all([
      getRiskSummary(),
      getEngineRegistry(),
      listDetections({ page: 1, page_size: 10 }),
      listIncidents({ page: 1, page_size: 10 }),
    ])
    summary.value = risk
    engines.value = registry
    topFindings.value = findings.items
    topIncidents.value = incidents.items
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
      <template v-if="summary">
        <div class="stat-grid cols-4">
          <StatCard label="总风险对象" :value="summary.count" />
          <StatCard label="最高风险评分" :value="summary.max_score" tone="danger" />
          <StatCard label="平均风险评分" :value="summary.avg_score" tone="warning" />
          <StatCard label="检测引擎" :value="engines.length" tone="info" />
        </div>

        <div class="grid cols-3" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot" />风险评分仪表</div>
            <GaugeChart :value="summary.avg_score" :height="240" />
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />资产风险分布</div>
            <DonutChart :data="assetRiskData" :height="240" />
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />数据敏感度分布</div>
            <DonutChart :data="dataSensitivityData" :height="240" />
          </div>
        </div>

        <div class="soc-card" style="margin-top: 12px">
          <div class="soc-card-title"><span class="dot" />引擎风险分布</div>
          <BarChart :x-data="engineData.x" :data="engineData.y" :height="260" />
        </div>

        <div class="grid cols-2" style="margin-top: 12px">
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot danger" />Top 风险检测</div>
            <el-table :data="topFindings" size="small" @row-click="() => router.push('/detections')">
              <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
              <el-table-column prop="rule_id" label="规则" min-width="150" show-overflow-tooltip />
              <el-table-column label="风险" width="80"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
              <el-table-column prop="engine" label="引擎" width="110" />
            </el-table>
          </div>
          <div class="soc-card">
            <div class="soc-card-title"><span class="dot warn" />Top 风险事件</div>
            <el-table :data="topIncidents" size="small" @row-click="() => router.push('/incidents')">
              <el-table-column label="时间" width="140"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
              <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
              <el-table-column prop="title" label="标题" min-width="160" show-overflow-tooltip />
              <el-table-column label="风险" width="80"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
            </el-table>
          </div>
        </div>
      </template>
    </StateBox>
  </div>
</template>
