<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import RiskScore from '../components/RiskScore.vue'
import FindingDrawer from '../components/FindingDrawer.vue'
import IncidentDrawer from '../components/IncidentDrawer.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listDetections, getDetection } from '../api/detections'
import { getIncident } from '../api/incidents'
import type { DetectionFinding } from '../types/finding'
import type { Incident } from '../types/incident'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<DetectionFinding[]>([])
const total = ref(0)
const selected = ref<DetectionFinding | null>(null)
const related = ref<Incident[]>([])
const findingVisible = ref(false)
const incident = ref<Incident | null>(null)
const incidentVisible = ref(false)
const filters = reactive({ severity: '', engine: '', risk_level: '', target_type: '', search: '', page: 1, page_size: 50 })

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

async function openFinding(row: DetectionFinding): Promise<void> {
  try {
    const detail = await getDetection(row.id)
    selected.value = detail.detection
    related.value = detail.related_incidents
    findingVisible.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function openIncident(row: Incident): Promise<void> {
  try {
    incident.value = await getIncident(row.id)
    incidentVisible.value = true
    findingVisible.value = false
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void {
  filters.page = 1
  load()
}

onMounted(load)
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-input v-model="filters.search" placeholder="搜索规则/引擎/建议" clearable @keyup.enter="reset" />
      <el-select v-model="filters.severity" placeholder="Severity" clearable>
        <el-option v-for="item in ['Critical', 'High', 'Medium', 'Low']" :key="item" :label="item" :value="item" />
      </el-select>
      <el-select v-model="filters.engine" placeholder="Engine" clearable>
        <el-option v-for="item in ['zeek', 'suricata', 'presidio', 'misp', 'osquery', 'wazuh', 'openscap', 'rules', 'data_engine', 'traffic_engine']" :key="item" :label="item" :value="item" />
      </el-select>
      <el-select v-model="filters.risk_level" placeholder="风险等级" clearable>
        <el-option v-for="item in ['Critical', 'High', 'Medium', 'Low']" :key="item" :label="item" :value="item" />
      </el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
      <el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column>
      <el-table-column prop="rule_id" label="规则" />
      <el-table-column prop="engine" label="Engine" />
      <el-table-column prop="target_type" label="Target" />
      <el-table-column label="置信度" width="90"><template #default="{ row }">{{ (row.confidence * 100).toFixed(0) }}%</template></el-table-column>
      <el-table-column label="风险" width="110"><template #default="{ row }"><RiskScore :score="row.risk_score" :level="row.risk_level" /></template></el-table-column>
      <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="openFinding(row)">查看</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <FindingDrawer v-model="findingVisible" :finding="selected" :related-incidents="related" @open-incident="openIncident" />
    <IncidentDrawer v-model="incidentVisible" :incident="incident" />
  </div>
</template>

<style scoped>
.pagination { margin-top: 14px; justify-content: flex-end; }
</style>
