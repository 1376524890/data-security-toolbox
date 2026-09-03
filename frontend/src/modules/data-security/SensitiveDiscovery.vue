<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { listDataAssets } from '../../api/dataAssets'
import { listDetections } from '../../api/detections'
import { getSensitiveFindings, type SensitiveFindings } from '../../api/dataAssets'
import { getRiskSummary } from '../../api/risk'
import type { DataAsset } from '../../types/dataAsset'
import type { DetectionFinding } from '../../types/finding'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import DonutChart from '../../components/charts/DonutChart.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import EvidenceViewer from '../../components/evidence/EvidenceViewer.vue'

const loading = ref(true)
const error = ref('')
const assets = ref<DataAsset[]>([])
const findings = ref<DetectionFinding[]>([])
const risk = ref<{ data_sensitivity: Record<string, number> } | null>(null)
const sensitive = ref<SensitiveFindings | null>(null)

const categoryLabels: Record<string, string> = {
  id_card: '身份证', phone: '手机号', bank_card: '银行卡', email: 'Email', medical: '医疗数据', secret: 'Secret',
}

const categoryCounts = computed(() => {
  const counts: Record<string, number> = {}
  sensitive.value?.categories.forEach((cat) => { counts[cat.category] = cat.count })
  return counts
})

const categoryData = computed(() => Object.entries(categoryCounts.value).map(([name, value]) => ({ name: categoryLabels[name] || name, value })))
const sensitivityData = computed(() => Object.entries(sensitive.value?.data_assets?.by_sensitivity || {}).map(([name, value]) => ({ name, value })))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [assetResult, findingResult, riskResult, sensitiveResult] = await Promise.all([
      listDataAssets({ page: 1, page_size: 200 }),
      listDetections({ engine: 'data', page: 1, page_size: 100 }),
      getRiskSummary(),
      getSensitiveFindings(),
    ])
    assets.value = assetResult.items
    findings.value = findingResult.items
    risk.value = riskResult
    sensitive.value = sensitiveResult
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
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="stat-grid cols-4">
        <StatCard label="数据资产" :value="assets.length" />
        <StatCard label="敏感检测" :value="findings.length" tone="warning" />
        <StatCard label="敏感类目" :value="Object.keys(categoryCounts).length" tone="primary" />
      </div>
      <div class="grid cols-2" style="margin-top: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />敏感类目分布</div>
          <DonutChart :data="categoryData" :height="280" />
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />数据敏感度分布</div>
          <DonutChart :data="sensitivityData" :height="280" />
        </div>
      </div>
      <div class="soc-card" style="margin-top: 12px">
        <div class="soc-card-title"><span class="dot danger" />敏感检测结果</div>
        <el-table :data="findings" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="engine" label="引擎" width="110" />
          <el-table-column prop="rule_id" label="规则" min-width="150" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
          <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
          <el-table-column label="证据" min-width="200"><template #default="{ row }"><EvidenceViewer :evidence="row.evidence" /></template></el-table-column>
        </el-table>
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.gap-note { color: var(--soc-warning); font-size: 11px; }
</style>
