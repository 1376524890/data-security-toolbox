<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listIocs, getIocAssociations } from '../api/intelligence'
import type { Ioc, IocAssociation } from '../types/ioc'
import { formatDateTime } from '../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Ioc[]>([])
const total = ref(0)
const detail = ref<IocAssociation | null>(null)
const drawer = ref(false)
const filters = reactive({ type: '', source: '', search: '', page: 1, page_size: 50 })

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listIocs({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Ioc): Promise<void> {
  try {
    detail.value = await getIocAssociations(row.id)
    drawer.value = true
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
      <el-input v-model="filters.search" placeholder="搜索 IOC 值" clearable @keyup.enter="reset" />
      <el-select v-model="filters.type" placeholder="类型" clearable><el-option v-for="item in ['ip', 'domain', 'url', 'hash']" :key="item" :label="item" :value="item" /></el-select>
      <el-select v-model="filters.source" placeholder="来源" clearable><el-option v-for="item in ['offline', 'MISP', 'test-upload', 'integration']" :key="item" :label="item" :value="item" /></el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column label="类型" width="90"><template #default="{ row }"><el-tag size="small">{{ row.type }}</el-tag></template></el-table-column>
      <el-table-column prop="value" label="Value" />
      <el-table-column prop="source" label="来源" />
      <el-table-column label="First Seen" width="160"><template #default="{ row }">{{ formatDateTime(row.first_seen) }}</template></el-table-column>
      <el-table-column label="Last Seen" width="160"><template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template></el-table-column>
      <el-table-column label="Tags" width="180"><template #default="{ row }">{{ row.tags.join(', ') || '-' }}</template></el-table-column>
      <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="open(row)">关联</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="IOC 关联" size="50%">
      <template v-if="detail">
        <el-descriptions :column="2" border><el-descriptions-item label="Value">{{ detail.ioc.value }}</el-descriptions-item><el-descriptions-item label="Type">{{ detail.ioc.type }}</el-descriptions-item></el-descriptions>
        <el-divider content-position="left">Findings</el-divider>
        <el-table :data="detail.findings" size="small"><el-table-column prop="rule_id" label="规则" /><el-table-column prop="engine" label="Engine" /><el-table-column label="风险" width="90"><template #default="{ row }"><SeverityBadge :value="row.risk_level" /></template></el-table-column></el-table>
        <el-divider content-position="left">Incidents</el-divider>
        <el-table :data="detail.incidents" size="small"><el-table-column prop="title" label="事件" /><el-table-column label="Severity" width="90"><template #default="{ row }"><SeverityBadge :value="row.severity" /></template></el-table-column></el-table>
        <el-divider content-position="left">Assets</el-divider>
        <el-table :data="detail.assets" size="small"><el-table-column prop="ip" label="IP" /><el-table-column prop="hostname" label="Host" /></el-table>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
