<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import StatusBadge from '../components/StatusBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import JsonViewer from '../components/JsonViewer.vue'
import { getAlert, listAlerts, updateAlert, type AlertQuery } from '../api/alerts'
import type { Alert, AlertDetail } from '../types/alert'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Alert[]>([])
const total = ref(0)
const drawer = ref(false)
const detail = ref<AlertDetail | null>(null)
const filters = reactive<AlertQuery>({ search: '', status: '', severity: '', page: 1, page_size: 50 })

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listAlerts({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Alert): Promise<void> {
  try {
    detail.value = await getAlert(row.id)
    drawer.value = true
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

async function acknowledge(row: Alert): Promise<void> {
  await updateAlert(row.id, { status: 'acknowledged' })
  ElMessage.success('已确认')
  await load()
}

async function resolve(row: Alert): Promise<void> {
  await updateAlert(row.id, { status: 'resolved' })
  ElMessage.success('已解决')
  await load()
}

async function openRefresh(): Promise<void> {
  if (detail.value) {
    detail.value = await getAlert(detail.value.alert.id)
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
      <el-input v-model="filters.search" placeholder="搜索标题/摘要" clearable @keyup.enter="reset" />
      <el-select v-model="filters.status" placeholder="状态" clearable><el-option v-for="item in ['new', 'acknowledged', 'resolved', 'suppressed']" :key="item" :label="item" :value="item" /></el-select>
      <el-select v-model="filters.severity" placeholder="等级" clearable><el-option v-for="item in ['Critical', 'High', 'Medium', 'Low']" :key="item" :label="item" :value="item" /></el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column label="Severity" width="100"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column>
      <el-table-column prop="title" label="标题" min-width="220" />
      <el-table-column prop="source" label="来源" width="120" />
      <el-table-column prop="risk_score" label="Risk" width="80" />
      <el-table-column prop="occurrence_count" label="次数" width="80" />
      <el-table-column label="状态" width="120"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
      <el-table-column label="Last Seen" width="170"><template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template></el-table-column>
      <el-table-column label="操作" width="230"><template #default="{ row }"><el-button link type="primary" @click="open(row)">详情</el-button><el-button link @click="acknowledge(row)">确认</el-button><el-button link @click="resolve(row)">解决</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="Alert Detail" size="62%">
      <template v-if="detail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Severity"><SeverityBadge :value="detail.alert.severity" /></el-descriptions-item>
          <el-descriptions-item label="Risk">{{ detail.alert.risk_score }}</el-descriptions-item>
          <el-descriptions-item label="Source">{{ detail.alert.source }}</el-descriptions-item>
          <el-descriptions-item label="Probe">{{ detail.probe?.name || detail.alert.probe_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="First Seen">{{ formatDateTime(detail.alert.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Last Seen">{{ formatDateTime(detail.alert.last_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Occurrences">{{ detail.alert.occurrence_count }}</el-descriptions-item>
          <el-descriptions-item label="Status"><StatusBadge :value="detail.alert.status" /></el-descriptions-item>
        </el-descriptions>
        <el-divider content-position="left">Related</el-divider>
        <el-table :data="[
          detail.finding ? { type: 'Finding', id: detail.finding.id, value: `${detail.finding.engine}/${detail.finding.rule_id}` } : null,
          detail.incident ? { type: 'Incident', id: detail.incident.id, value: detail.incident.title } : null,
          detail.pcap ? { type: 'PCAP', id: detail.pcap.id, value: detail.pcap.filename } : null,
        ].filter(Boolean)" size="small">
          <el-table-column prop="type" label="类型" width="120" />
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="value" label="值" />
        </el-table>
        <div class="actions">
          <el-button type="primary" @click="updateAlert(detail.alert.id, { status: 'acknowledged' }).then(openRefresh)">Acknowledge</el-button>
          <el-button type="success" @click="updateAlert(detail.alert.id, { status: 'resolved' }).then(openRefresh)">Resolve</el-button>
          <el-button type="warning" @click="updateAlert(detail.alert.id, { status: 'suppressed' }).then(openRefresh)">Suppress</el-button>
          <el-button @click="openRefresh()">刷新</el-button>
        </div>
        <el-divider content-position="left">Evidence</el-divider>
        <JsonViewer :value="{ finding: detail.finding, incident: detail.incident, pcap: detail.pcap, deliveries: detail.deliveries }" title="Evidence" />
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.pagination { margin-top: 14px; justify-content: flex-end; }
.actions { margin-top: 12px; }
</style>
