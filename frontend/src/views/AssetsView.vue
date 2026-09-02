<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import { listAssets, getAsset } from '../api/assets'
import type { Asset, AssetDetail } from '../types/asset'

const loading = ref(true)
const error = ref('')
const items = ref<Asset[]>([])
const total = ref(0)
const detail = ref<AssetDetail | null>(null)
const drawer = ref(false)
const filters = reactive({ risk: '', asset_type: '', search: '', page: 1, page_size: 50 })

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listAssets({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Asset): Promise<void> {
  try {
    detail.value = await getAsset(row.id)
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
      <el-input v-model="filters.search" placeholder="搜索 IP/主机/服务" clearable @keyup.enter="reset" />
      <el-select v-model="filters.risk" placeholder="风险" clearable><el-option v-for="item in ['Critical', 'High', 'Medium', 'Low']" :key="item" :label="item" :value="item" /></el-select>
      <el-select v-model="filters.asset_type" placeholder="类型" clearable><el-option v-for="item in ['host', 'web', 'database', 'file', 'network', 'service']" :key="item" :label="item" :value="item" /></el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column prop="ip" label="IP" />
      <el-table-column prop="hostname" label="Host" />
      <el-table-column prop="os" label="OS" />
      <el-table-column prop="service" label="服务" />
      <el-table-column prop="port" label="端口" />
      <el-table-column prop="asset_type" label="类型" />
      <el-table-column label="风险" width="90"><template #default="{ row }"><SeverityBadge :value="row.risk_level" /></template></el-table-column>
      <el-table-column label="敏感分类" width="180"><template #default="{ row }">{{ row.sensitive_categories.join(', ') || '-' }}</template></el-table-column>
      <el-table-column label="Last Seen" width="150"><template #default="{ row }">{{ row.last_seen || '-' }}</template></el-table-column>
      <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="open(row)">详情</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="资产详情" size="48%">
      <template v-if="detail">
        <el-descriptions :column="2" border><el-descriptions-item label="IP">{{ detail.asset.ip }}</el-descriptions-item><el-descriptions-item label="主机">{{ detail.asset.hostname }}</el-descriptions-item><el-descriptions-item label="OS">{{ detail.asset.os }}</el-descriptions-item><el-descriptions-item label="服务">{{ detail.asset.service }}</el-descriptions-item></el-descriptions>
        <el-divider content-position="left">风险 Finding</el-divider>
        <el-table :data="detail.findings" size="small"><el-table-column prop="rule_id" label="规则" /><el-table-column prop="engine" label="Engine" /><el-table-column label="风险" width="90"><template #default="{ row }"><SeverityBadge :value="row.risk_level" /></template></el-table-column></el-table>
        <el-divider content-position="left">数据资产</el-divider>
        <el-table :data="detail.data_assets" size="small"><el-table-column prop="name" label="名称" /><el-table-column prop="sensitivity" label="敏感度" /></el-table>
        <el-divider content-position="left">IOC</el-divider>
        <el-table :data="detail.iocs" size="small"><el-table-column prop="value" label="Value" /><el-table-column prop="type" label="Type" /></el-table>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
