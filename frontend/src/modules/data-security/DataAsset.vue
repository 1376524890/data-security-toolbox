<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { listDataAssets, getDataAsset } from '../../api/dataAssets'
import { listProbes, collectProbeDataAssets, type Probe } from '../../api/probes'
import { getTask } from '../../api/tasks'
import type { DataAsset as DataAssetType, DataAssetDetail } from '../../types/dataAsset'
import StateBox from '../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../components/common/FilterBar.vue'
import DetailDrawer from '../../components/common/DetailDrawer.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import DataRiskCard from '../../components/security/DataRiskCard.vue'
import JsonViewer from '../../components/evidence/JsonViewer.vue'

const loading = ref(true)
const error = ref('')
const items = ref<DataAssetType[]>([])
const total = ref(0)
const detail = ref<DataAssetDetail | null>(null)
const drawer = ref(false)
const filters = reactive({ search: '', sensitivity: '', asset_type: '', source: '', probe_id: '', page: 1, page_size: 50 })

const probes = ref<Probe[]>([])
const collectDialog = ref(false)
const collecting = ref(false)
const collectProgress = ref(0)
const collectStage = ref('')
const collectForm = reactive({ probe_id: null as number | null, pathsText: '', max_files: 200, max_depth: 3, timeout_seconds: 120, include_databases: true })

const filterFields = computed<FilterField[]>(() => [
  { key: 'search', label: '搜索名称', placeholder: '搜索资产名称', width: '200px' },
  { key: 'sensitivity', label: '敏感度', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '110px' },
  { key: 'asset_type', label: '类型', type: 'select', options: ['table', 'file', 'database', 'directory'].map((v) => ({ label: v, value: v })), width: '120px' },
  { key: 'probe_id', label: '探针', type: 'select', placeholder: '全部探针', options: probes.value.map((p) => ({ label: `${p.name} (${p.ip_address || '未知IP'})`, value: String(p.id) })), width: '200px' },
])

const piiData = computed(() => Object.entries(detail.value?.pii_summary || {}).map(([name, value]) => ({ name, value })))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const result = await listDataAssets({
      search: filters.search,
      sensitivity: filters.sensitivity,
      asset_type: filters.asset_type,
      source: filters.source,
      probe_id: filters.probe_id ? Number(filters.probe_id) : undefined,
      page: filters.page,
      page_size: filters.page_size,
    })
    items.value = result.items
    total.value = result.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function loadProbes(): Promise<void> {
  try {
    const result = await listProbes({ page: 1, page_size: 200 })
    probes.value = result.items
  } catch {
    probes.value = []
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

function openCollect(): void {
  collectDialog.value = true
  collectProgress.value = 0
  collectStage.value = ''
}

async function submitCollect(): Promise<void> {
  if (!collectForm.probe_id) { ElMessage.warning('请选择探针'); return }
  const paths = collectForm.pathsText.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)
  if (!paths.length) { ElMessage.warning('请填写至少一个采集目录（绝对路径），例如 /srv/data'); return }
  collecting.value = true
  collectProgress.value = 5
  collectStage.value = '下发采集任务'
  try {
    const task = await collectProbeDataAssets(collectForm.probe_id, {
      paths,
      max_files: collectForm.max_files,
      max_depth: collectForm.max_depth,
      timeout_seconds: collectForm.timeout_seconds,
      include_databases: collectForm.include_databases,
    })
    for (let i = 0; i < 100; i++) {
      await new Promise((resolve) => setTimeout(resolve, 3000))
      const current = await getTask(task.id)
      collectProgress.value = current.progress ?? collectProgress.value
      collectStage.value = current.current_stage || collectStage.value
      if (['Success', 'Partial', 'Failed', 'Failure'].includes(current.status)) {
        collectProgress.value = 100
        if (current.status === 'Failed' || current.status === 'Failure') throw new Error(current.error || '采集失败')
        ElMessage.success(`数据资产采集完成：${(current.result as { assets?: number })?.assets ?? 0} 个资产`)
        collectDialog.value = false
        load()
        return
      }
    }
    throw new Error('采集超时，请稍后在任务中心查看结果')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    collecting.value = false
  }
}

onMounted(() => { load(); loadProbes() })
</script>

<template>
  <div>
    <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
      <template #actions>
        <el-button type="primary" @click="openCollect">从探针采集数据资产</el-button>
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
          <el-table-column prop="value" label="数量" width="90" />
        </el-table>

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
        <el-form-item label="文件上限"><el-input-number v-model="collectForm.max_files" :min="1" :max="2000" /></el-form-item>
        <el-form-item label="执行时限（秒）"><el-input-number v-model="collectForm.timeout_seconds" :min="5" :max="1800" /></el-form-item>
        <el-form-item label="目录深度"><el-input-number v-model="collectForm.max_depth" :min="0" :max="8" /></el-form-item>
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
.data-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
@media (max-width: 1200px) { .data-cards { grid-template-columns: repeat(2, 1fr); } }
</style>
