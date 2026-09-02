<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import RiskScore from '../components/RiskScore.vue'
import StatusBadge from '../components/StatusBadge.vue'
import IncidentDrawer from '../components/IncidentDrawer.vue'
import FindingDrawer from '../components/FindingDrawer.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listIncidents, getIncident, updateIncidentStatus } from '../api/incidents'
import { getDetection } from '../api/detections'
import type { Incident } from '../types/incident'
import type { DetectionFinding } from '../types/finding'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Incident[]>([])
const total = ref(0)
const selected = ref<Incident | null>(null)
const selectedFinding = ref<DetectionFinding | null>(null)
const related = ref<Incident[]>([])
const incidentVisible = ref(false)
const findingVisible = ref(false)
const filters = reactive({ severity: '', status: '', search: '', start_time: '', end_time: '', page: 1, page_size: 50 })

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listIncidents({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function openIncident(row: Incident): Promise<void> {
  try {
    selected.value = await getIncident(row.id)
    incidentVisible.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function openFinding(finding: DetectionFinding): Promise<void> {
  try {
    const detail = await getDetection(finding.id)
    selectedFinding.value = detail.detection
    related.value = detail.related_incidents
    incidentVisible.value = false
    findingVisible.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function changeStatus(row: Incident, status: string): Promise<void> {
  try {
    await updateIncidentStatus(row.id, status)
    ElMessage.success('状态已更新')
    load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }
onMounted(load)
</script>

<template>
  <div class="page-card">
    <div class="toolbar">
      <el-input v-model="filters.search" placeholder="搜索标题/资产/IOC" clearable @keyup.enter="reset" />
      <el-select v-model="filters.severity" placeholder="Severity" clearable><el-option v-for="item in ['Critical', 'High', 'Medium', 'Low']" :key="item" :label="item" :value="item" /></el-select>
      <el-select v-model="filters.status" placeholder="状态" clearable><el-option v-for="item in ['open', 'investigating', 'closed']" :key="item" :label="item" :value="item" /></el-select>
      <el-date-picker v-model="filters.start_time" type="datetime" placeholder="开始时间" />
      <el-date-picker v-model="filters.end_time" type="datetime" placeholder="结束时间" />
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
      <el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column>
      <el-table-column prop="title" label="Title" />
      <el-table-column label="资产" width="130"><template #default="{ row }">{{ row.evidence?.asset || '-' }}</template></el-table-column>
      <el-table-column label="IOC" width="150"><template #default="{ row }">{{ row.evidence?.ioc || '-' }}</template></el-table-column>
      <el-table-column label="阶段" width="130"><template #default="{ row }">{{ (row.evidence?.stages || []).join(' → ') }}</template></el-table-column>
      <el-table-column label="Findings" width="80"><template #default="{ row }">{{ row.findings?.items?.length || 0 }}</template></el-table-column>
      <el-table-column label="置信度" width="90"><template #default="{ row }">{{ (row.confidence * 100).toFixed(0) }}%</template></el-table-column>
      <el-table-column label="风险" width="110"><template #default="{ row }"><RiskScore :score="row.risk_score" :level="row.risk_level" /></template></el-table-column>
      <el-table-column label="状态" width="110"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
      <el-table-column label="操作" width="170">
        <template #default="{ row }">
          <el-button link type="primary" @click="openIncident(row)">详情</el-button>
          <el-dropdown @command="(status: string) => changeStatus(row, status)"><el-button link>状态</el-button><template #dropdown><el-dropdown-menu><el-dropdown-item command="investigating">调查中</el-dropdown-item><el-dropdown-item command="closed">关闭</el-dropdown-item></el-dropdown-menu></template></el-dropdown>
        </template>
      </el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <IncidentDrawer v-model="incidentVisible" :incident="selected" @open-finding="openFinding" />
    <FindingDrawer v-model="findingVisible" :finding="selectedFinding" :related-incidents="related" />
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
