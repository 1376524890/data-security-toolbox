<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { listDetections, getDetection, type DetectionQuery } from '../../../api/detections'
import type { DetectionFinding, FindingDetail } from '../../../types/finding'
import StateBox from '../../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../../components/common/FilterBar.vue'
import DetailDrawer from '../../../components/common/DetailDrawer.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import RiskBadge from '../../../components/security/RiskBadge.vue'
import EvidenceViewer from '../../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { formatDateTime } from '../../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<DetectionFinding[]>([])
const total = ref(0)
const detail = ref<FindingDetail | null>(null)
const drawer = ref(false)
const filters = reactive<DetectionQuery>({ search: '', severity: '', engine: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索 Rule/Engine', placeholder: '搜索 Rule / Engine / 建议', width: '240px' },
  { key: 'severity', label: '等级', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'engine', label: '引擎', type: 'select', options: ['traffic', 'protocol', 'zeek', 'suricata', 'data', 'sigma', 'ioc', 'compliance'].map((v) => ({ label: v, value: v })), width: '140px' },
]

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listDetections({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: DetectionFinding): Promise<void> {
  try {
    detail.value = await getDetection(row.id)
    drawer.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column label="时间" width="160"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
        <el-table-column prop="engine" label="引擎" width="120" />
        <el-table-column prop="rule_id" label="规则" min-width="180" show-overflow-tooltip />
        <el-table-column label="等级" width="100"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
        <el-table-column label="置信度" width="100"><template #default="{ row }"><span class="mono">{{ (row.confidence * 100).toFixed(0) }}%</span></template></el-table-column>
        <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :score="row.risk_score" :level="row.risk_level" /></template></el-table-column>
        <el-table-column label="目标" width="160"><template #default="{ row }"><span class="mono">{{ row.target_type }}:{{ row.target_id }}</span></template></el-table-column>
        <el-table-column prop="recommendation" label="处置建议" min-width="200" show-overflow-tooltip />
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="检测详情" width="60%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="ID"><span class="mono">#{{ detail.detection.id }}</span></el-descriptions-item>
          <el-descriptions-item label="引擎">{{ detail.detection.engine }}</el-descriptions-item>
          <el-descriptions-item label="规则"><span class="mono">{{ detail.detection.rule_id }}</span></el-descriptions-item>
          <el-descriptions-item label="等级"><SeverityTag :value="detail.detection.severity" /></el-descriptions-item>
          <el-descriptions-item label="置信度"><span class="mono">{{ (detail.detection.confidence * 100).toFixed(0) }}%</span></el-descriptions-item>
          <el-descriptions-item label="风险"><RiskBadge :score="detail.detection.risk_score" /></el-descriptions-item>
          <el-descriptions-item label="目标"><span class="mono">{{ detail.detection.target_type }}:{{ detail.detection.target_id }}</span></el-descriptions-item>
          <el-descriptions-item label="时间"><span class="mono">{{ formatDateTime(detail.detection.timestamp) }}</span></el-descriptions-item>
          <el-descriptions-item label="创建时间"><span class="mono">{{ formatDateTime(detail.detection.created_at) }}</span></el-descriptions-item>
        </el-descriptions>
        <div class="drawer-section">
          <div class="sec-title">证据</div>
          <EvidenceViewer :evidence="detail.detection.evidence" />
          <JsonViewer :value="{ detection: detail.detection, related_incidents: detail.related_incidents, alert: detail.alert, pcap: detail.pcap }" title="完整 JSON" :height="280" />
        </div>
      </template>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.drawer-section { margin-top: 16px; }
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
