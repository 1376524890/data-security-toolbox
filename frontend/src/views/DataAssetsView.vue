<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import SeverityBadge from '../components/SeverityBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import ErrorState from '../components/ErrorState.vue'
import LoadingState from '../components/LoadingState.vue'
import JsonViewer from '../components/JsonViewer.vue'
import { listDataAssets, getDataAsset } from '../api/dataAssets'
import type { DataAsset, DataAssetDetail } from '../types/dataAsset'

const loading = ref(true)
const error = ref('')
const items = ref<DataAsset[]>([])
const total = ref(0)
const detail = ref<DataAssetDetail | null>(null)
const drawer = ref(false)
const filters = reactive({ search: '', sensitivity: '', asset_type: '', source: '', page: 1, page_size: 50 })

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listDataAssets({ ...filters })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: DataAsset): Promise<void> {
  try {
    detail.value = await getDataAsset(row.id)
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
      <el-input v-model="filters.search" placeholder="搜索数据资产名称" clearable @keyup.enter="reset" />
      <el-select v-model="filters.sensitivity" placeholder="敏感度" clearable><el-option v-for="item in ['Critical', 'High', 'Medium', 'Low']" :key="item" :label="item" :value="item" /></el-select>
      <el-select v-model="filters.asset_type" placeholder="类型" clearable><el-option v-for="item in ['file', 'database', 'table']" :key="item" :label="item" :value="item" /></el-select>
      <el-button type="primary" @click="reset">查询</el-button>
    </div>
    <LoadingState v-if="loading" />
    <ErrorState v-else-if="error" :message="error" @retry="load" />
    <EmptyState v-else-if="!items.length" />
    <el-table v-else :data="items" stripe>
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="asset_type" label="类型" />
      <el-table-column prop="source" label="来源" />
      <el-table-column label="敏感度" width="90"><template #default="{ row }"><SeverityBadge :value="row.sensitivity" /></template></el-table-column>
      <el-table-column label="字段数" width="80"><template #default="{ row }">{{ row.columns.length }}</template></el-table-column>
      <el-table-column label="操作" width="80"><template #default="{ row }"><el-button link type="primary" @click="open(row)">详情</el-button></template></el-table-column>
    </el-table>
    <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(page: number) => { filters.page = page; load() }" />
    <el-drawer v-model="drawer" title="数据资产详情" size="48%">
      <template v-if="detail">
        <el-descriptions :column="2" border><el-descriptions-item label="名称">{{ detail.data_asset.name }}</el-descriptions-item><el-descriptions-item label="类型">{{ detail.data_asset.asset_type }}</el-descriptions-item><el-descriptions-item label="来源">{{ detail.data_asset.source }}</el-descriptions-item><el-descriptions-item label="敏感度">{{ detail.data_asset.sensitivity }}</el-descriptions-item></el-descriptions>
        <el-divider content-position="left">字段</el-divider>
        <el-table :data="detail.data_asset.columns" size="small">
          <el-table-column prop="name" label="字段" />
          <el-table-column prop="detected_type" label="检测类型" />
          <el-table-column prop="sensitivity" label="敏感度" />
          <el-table-column prop="confidence" label="置信度" />
          <el-table-column prop="count" label="数量" />
        </el-table>
        <el-divider content-position="left">PII Summary</el-divider>
        <el-descriptions :column="2" border><el-descriptions-item v-for="(value, key) in detail.pii_summary" :key="key" :label="key">{{ value }}</el-descriptions-item></el-descriptions>
        <el-divider content-position="left">原始样本</el-divider>
        <JsonViewer :value="detail.data_asset" title="查看脱敏样本" masked />
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>.pagination { margin-top: 14px; justify-content: flex-end; }</style>
