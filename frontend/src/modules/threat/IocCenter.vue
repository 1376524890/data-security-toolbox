<script setup lang="ts">
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import EvidenceViewer from '../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'
import { formatDateTime } from '../../utils/format'
import IntelligenceSources from './IntelligenceSources.vue'
import { useIocCenter } from './composables/useIocCenter'

// The inventory, the association drawer and the toggle live in the composable;
// this view keeps the static filter fields and binds the state into the
// template below.
const {
  loading, error, items, total, detail, drawer, filters, load, open, reset, toggle,
} = useIocCenter()

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索值', placeholder: '搜索指标', width: '220px' },
  { key: 'type', label: '类型', type: 'select', options: ['ip', 'domain', 'url', 'hash', 'email', 'file'].map((v) => ({ label: v, value: v })), width: '120px' },
  { key: 'source', label: '来源', type: 'select', options: ['misp', 'offline', 'manual'].map((v) => ({ label: v, value: v })), width: '120px' },
]

</script>

<template>
  <div>
    <IntelligenceSources @changed="load" />
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column label="启用" width="80"><template #default="{row}"><el-switch :model-value="row.metadata?.enabled !== false" @click.stop @change="toggle(row)" /></template></el-table-column>
        <el-table-column prop="value" label="指标" min-width="200" show-overflow-tooltip />
        <el-table-column prop="type" label="类型" width="100" />
        <el-table-column prop="source" label="来源" width="110" />
        <el-table-column label="首次发现" width="160"><template #default="{ row }">{{ formatDateTime(row.first_seen) }}</template></el-table-column>
        <el-table-column label="最近发现" width="160"><template #default="{ row }">{{ formatDateTime(row.last_seen) }}</template></el-table-column>
        <el-table-column label="标签" min-width="140"><template #default="{ row }"><el-tag v-for="t in row.tags || []" :key="t" size="small">{{ t }}</el-tag></template></el-table-column>
      </el-table>
      <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
    </StateBox>

    <DetailDrawer v-model="drawer" title="IOC 详情" width="62%">
      <template v-if="detail">
        <el-descriptions :column="3" border size="small">
          <el-descriptions-item label="指标"><span class="mono">{{ detail.ioc.value }}</span></el-descriptions-item>
          <el-descriptions-item label="类型">{{ detail.ioc.type }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ detail.ioc.source }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ formatDateTime(detail.ioc.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="最近发现">{{ formatDateTime(detail.ioc.last_seen) }}</el-descriptions-item>
        </el-descriptions>

        <div class="sec-title" style="margin-top: 14px">关联检测</div>
        <el-table :data="detail.findings" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="engine" label="引擎" width="120" />
          <el-table-column prop="rule_id" label="规则" min-width="140" />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
        </el-table>

        <div class="sec-title" style="margin-top: 14px">关联事件</div>
        <el-table :data="detail.incidents" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="title" label="标题" min-width="180" />
          <el-table-column label="状态" width="110"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        </el-table>

        <div class="sec-title" style="margin-top: 14px">关联资产</div>
        <el-table :data="detail.assets" size="small">
          <el-table-column prop="ip" label="IP" width="140" />
          <el-table-column prop="hostname" label="主机名" min-width="140" />
        </el-table>
      </template>
    </DetailDrawer>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
</style>
