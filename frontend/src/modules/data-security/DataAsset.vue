<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { listDataAssets, getDataAsset } from '../../api/dataAssets'
import type { DataAsset as DataAssetType, DataAssetDetail } from '../../types/dataAsset'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import DataRiskCard from '../../components/security/DataRiskCard.vue'
import EvidenceViewer from '../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'

const loading = ref(true)
const error = ref('')
const items = ref<DataAssetType[]>([])
const total = ref(0)
const detail = ref<DataAssetDetail | null>(null)
const drawer = ref(false)
const filters = reactive({ search: '', sensitivity: '', asset_type: '', source: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索名称', placeholder: '搜索资产名称', width: '200px' },
  { key: 'sensitivity', label: '敏感度', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'asset_type', label: '类型', type: 'select', options: ['table', 'file', 'database', 'api'].map((v) => ({ label: v, value: v })), width: '120px' },
]

const piiData = computed(() => Object.entries(detail.value?.pii_summary || {}).map(([name, value]) => ({ name, value })))

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

async function open(row: DataAssetType): Promise<void> {
  try {
    detail.value = await getDataAsset(row.id)
    drawer.value = true
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <div class="data-cards" style="margin-bottom: 12px">
        <div v-for="a in items.slice(0, 8)" :key="a.id" class="data-card-wrap" @click="open(a)">
          <DataRiskCard :asset="a" />
        </div>
      </div>
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="asset_type" label="类型" width="120" />
        <el-table-column label="敏感等级" width="100"><template #default="{ row }"><RiskBadge :level="row.sensitivity" /></template></el-table-column>
        <el-table-column prop="source" label="来源" min-width="140" show-overflow-tooltip />
        <el-table-column label="字段数" width="80"><template #default="{ row }">{{ row.columns?.length || 0 }}</template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="数据资产详情" width="62%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="名称">{{ detail.data_asset.name }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ detail.data_asset.asset_type }}</el-descriptions-item>
          <el-descriptions-item label="敏感等级"><RiskBadge :level="detail.data_asset.sensitivity" /></el-descriptions-item>
          <el-descriptions-item label="来源"><span class="mono">{{ detail.data_asset.source }}</span></el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ detail.data_asset.created_at }}</el-descriptions-item>
        </el-descriptions>

        <div class="sec-title" style="margin-top: 14px">字段</div>
        <el-table :data="detail.data_asset.columns" size="small">
          <el-table-column prop="name" label="字段名" min-width="140" />
          <el-table-column label="类型" width="110"><template #default="{ row }">{{ row.detected_type || row.sensitivity || '-' }}</template></el-table-column>
          <el-table-column label="置信度" width="90"><template #default="{ row }">{{ row.confidence != null ? (row.confidence * 100).toFixed(0) + '%' : '-' }}</template></el-table-column>
          <el-table-column label="类目" min-width="140"><template #default="{ row }"><el-tag v-for="c in row.categories || []" :key="c" size="small">{{ c }}</el-tag></template></el-table-column>
          <el-table-column prop="count" label="数量" width="70" />
        </el-table>

        <div class="sec-title" style="margin-top: 14px">PII 汇总</div>
        <el-table :data="piiData" size="small">
          <el-table-column prop="name" label="类目" min-width="140" />
          <el-table-column prop="value" label="数量" width="90" />
        </el-table>

        <div class="sec-title" style="margin-top: 14px">关联检测</div>
        <el-table :data="detail.findings" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="engine" label="引擎" width="120" />
          <el-table-column prop="rule_id" label="规则" min-width="140" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
        </el-table>
      </template>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
.data-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
@media (max-width: 1200px) { .data-cards { grid-template-columns: repeat(2, 1fr); } }
</style>
