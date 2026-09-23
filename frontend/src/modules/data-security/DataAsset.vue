<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import DataRiskCard from '../../components/security/DataRiskCard.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'

import { useDataAssetList } from './composables/useDataAssetList'
import { useDataAssetCollection } from './composables/useDataAssetCollection'

const router = useRouter()
const { loading, error, items, total, detail, drawer, filters, probes, piiData,
  load, loadProbes, open, reset } = useDataAssetList()
const { collectDialog, collecting, collectProgress, collectStage, collectForm,
  openCollect, submitCollect } = useDataAssetCollection(load)
const filterFields = computed<FilterField[]>(() => [
  { key: 'search', label: '搜索名称', placeholder: '搜索资产名称', width: '200px' },
  { key: 'sensitivity', label: '敏感度', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'asset_type', label: '类型', type: 'select', options: ['table', 'file', 'database', 'directory'].map((v) => ({ label: v, value: v })), width: '120px' },
  { key: 'probe_id', label: '探针', type: 'select', placeholder: '全部探针', options: probes.value.map((p) => ({ label: `${p.name} (${p.ip_address || '未知IP'})`, value: String(p.id) })), width: '200px' },
])

onMounted(() => { load(); loadProbes() })
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions>
        <el-button type="primary" @click="openCollect">从探针采集数据资产</el-button>
        <!-- The legacy projection stays the entry point; the object model is a
             separate view so this page keeps its existing meaning. -->
        <el-button @click="router.push('/data-types')">按数据类型查看</el-button>
        <el-button @click="router.push('/data-asset-jobs')">采集任务与进度</el-button>
      </template>
    </FilterBar>
    <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
      <div class="data-cards" style="margin-bottom: 12px">
        <div v-for="a in items.slice(0, 8)" :key="a.id" class="data-card-wrap" @click="open(a)">
          <DataRiskCard :asset="a" />
        </div>
      </div>
      <el-table :data="items" size="small" @row-click="open">
        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="asset_type" label="类型" width="110" />
        <el-table-column label="敏感等级" width="100"><template #default="{ row }"><RiskBadge :level="row.sensitivity" /></template></el-table-column>
        <el-table-column prop="source" label="来源" min-width="150" show-overflow-tooltip />
        <el-table-column label="主机" width="140"><template #default="{ row }"><span class="mono">{{ row.host || '-' }}</span></template></el-table-column>
        <el-table-column label="字段数" width="80"><template #default="{ row }">{{ row.columns?.length || 0 }}</template></el-table-column>
        <el-table-column label="状态" width="110"><template #default="{ row }"><StatusBadge :value="row.status || 'observed'" /></template></el-table-column>
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
          <el-descriptions-item label="探针">{{ detail.data_asset.probe || '-' }}</el-descriptions-item>
          <el-descriptions-item label="主机"><span class="mono">{{ detail.data_asset.host || '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="路径" :span="2"><span class="mono">{{ detail.data_asset.path || '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="状态">{{ detail.data_asset.status || 'observed' }}</el-descriptions-item>
          <el-descriptions-item label="发现时间">{{ detail.data_asset.observed_at || detail.data_asset.created_at }}</el-descriptions-item>
        </el-descriptions>

        <div class="sec-title" style="margin-top: 14px">敏感类目</div>
        <div style="display: flex; gap: 6px; flex-wrap: wrap">
          <el-tag v-for="c in detail.data_asset.categories || []" :key="c" size="small">{{ c }}</el-tag>
          <span v-if="!(detail.data_asset.categories || []).length" class="text-muted" style="font-size: 12px">未识别到敏感类目</span>
        </div>

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
          <el-table-column prop="fields" label="敏感字段数" width="110" />
          <el-table-column prop="sample_hits" label="样本命中次数" width="120" />
        </el-table>
        <div v-if="detail?.summary" class="pii-note">
          共 {{ detail.summary.sensitive_field_count ?? 0 }} 个敏感字段、
          {{ detail.summary.sample_hits ?? 0 }} 次样本命中；{{ detail.summary.note }}
        </div>

        <div class="sec-title" style="margin-top: 14px">关联检测</div>
        <el-table :data="detail.findings" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="engine" label="引擎" width="120" />
          <el-table-column prop="rule_id" label="规则" min-width="140" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
        </el-table>

        <div class="sec-title" style="margin-top: 14px">采集证据</div>
        <JsonViewer :value="detail.data_asset.extra || {}" :height="200" />
      </template>
    </DetailDrawer>

    <el-dialog v-model="collectDialog" title="从探针采集数据资产" width="560px" :close-on-click-modal="false">
      <el-alert type="info" :closable="false" title="探针会在目标服务器本地枚举目录与数据库服务，仅上传文件名、字段与敏感类目统计，不上传原始数据。" />
      <el-form label-width="120px" style="margin-top: 14px" :disabled="collecting">
        <el-form-item label="探针" required>
          <el-select v-model="collectForm.probe_id" placeholder="选择探针" filterable style="width: 100%">
            <el-option v-for="p in probes" :key="p.id" :value="p.id" :label="`${p.name} (${p.ip_address || '未知IP'})`" />
          </el-select>
        </el-form-item>
        <el-form-item label="采集目录" required>
          <el-input v-model="collectForm.pathsText" type="textarea" :rows="4" placeholder="每行一个绝对路径，例如：&#10;/srv/data&#10;/var/www/uploads" />
        </el-form-item>
        <el-form-item label="文件上限"><el-input-number v-model="collectForm.max_files" :min="0" :max="100000" /><span class="muted" style="margin-left: 8px">0 = 不限制</span></el-form-item>
        <el-form-item label="执行时限（秒）"><el-input-number v-model="collectForm.timeout_seconds" :min="0" :max="31536000" /><span class="muted" style="margin-left: 8px">0 = 不限制</span></el-form-item>
        <el-form-item label="目录深度"><el-input-number v-model="collectForm.max_depth" :min="0" :max="64" /><span class="muted" style="margin-left: 8px">0 = 不限制（扫描整棵目录树）</span></el-form-item>
        <el-form-item label="数据库服务"><el-switch v-model="collectForm.include_databases" /></el-form-item>
      </el-form>
      <el-progress v-if="collecting" :percentage="collectProgress" :stroke-width="10" />
      <div v-if="collecting" class="text-muted" style="font-size: 12px; margin-top: 4px">{{ collectStage }}</div>
      <template #footer>
        <el-button :disabled="collecting" @click="collectDialog = false">取消</el-button>
        <el-button type="primary" :loading="collecting" @click="submitCollect">开始采集</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
.pii-note { margin-top: 6px; font-size: 12px; color: var(--el-text-color-secondary); }
.data-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
@media (max-width: 1200px) { .data-cards { grid-template-columns: repeat(2, 1fr); } }
</style>
