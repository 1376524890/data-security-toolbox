<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { listIncidents, getIncident, updateIncidentStatus, correlateIncidents } from '../../../api/incidents'
import type { Incident, IncidentFilters, AttackStage } from '../../../types/incident'
import { incidentStages } from '../../../types/incident'

import StateBox from '../../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../../components/common/FilterBar.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import StatusBadge from '../../../components/security/StatusBadge.vue'
import RiskBadge from '../../../components/security/RiskBadge.vue'
import EvidenceViewer from '../../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import { formatDateTime, formatRiskScore } from '../../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Incident[]>([])
const total = ref(0)
const selected = ref<Incident | null>(null)
const detail = ref<Incident | null>(null)
const detailLoading = ref(false)
const filters = reactive<IncidentFilters>({ search: '', status: '', severity: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索标题', placeholder: '搜索标题 / 资产 / IOC', width: '240px' },
  { key: 'severity', label: '等级', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '120px' },
  { key: 'status', label: '状态', type: 'select', options: ['open', 'investigating', 'contained', 'resolved', 'closed'].map((v) => ({ label: v, value: v })), width: '140px' },
]

const stages: { key: AttackStage; label: string }[] = [
  { key: 'recon', label: '侦察' },
  { key: 'exploit', label: '扫描' },
  { key: 'credential', label: '凭据' },
  { key: 'c2', label: 'C2 通信' },
  { key: 'exfil', label: '数据外泄' },
  { key: 'impact', label: '影响' },
]

const activeStages = computed(() => { const inc = detail.value || selected.value; return inc ? incidentStages(inc) : [] })
const findings = computed(() => detail.value?.findings?.items || [])

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

async function open(row: Incident): Promise<void> {
  selected.value = row
  detailLoading.value = true
  try {
    detail.value = await getIncident(row.id)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    detailLoading.value = false
  }
}

async function changeStatus(status: string): Promise<void> {
  if (!selected.value) return
  try {
    await updateIncidentStatus(selected.value.id, status)
    ElMessage.success(`状态已更新为 ${status}`)
    await open(selected.value)
    await load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }

// --- Manual incident correlation ---
const correlateOpen = ref(false)
const correlateRunning = ref(false)
const correlateFindings = ref('')
const correlateWindow = ref(3600)
const correlateResult = ref<Array<Record<string, unknown>>>([])

async function runCorrelate(): Promise<void> {
  if (!correlateFindings.value.trim()) {
    ElMessage.warning('请输入待关联的发现 JSON')
    return
  }
  correlateRunning.value = true
  correlateResult.value = []
  try {
    const findings = JSON.parse(correlateFindings.value)
    if (!Array.isArray(findings)) throw new Error('发现必须是一个数组')
    correlateResult.value = await correlateIncidents(findings as Array<Record<string, unknown>>, correlateWindow.value)
    ElMessage.success(`关联完成，共生成 ${correlateResult.value.length} 个事件`)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    correlateRunning.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="incident-center">
    <div class="incident-list">
      <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset">
        <template #actions>
          <el-button type="primary" plain @click="correlateOpen = true"><el-icon><Connection /></el-icon>&nbsp;手工关联</el-button>
        </template>
      </FilterBar>
      <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
        <el-table :data="items" size="small" :row-class-name="({ row }: any) => row.id === selected?.id ? 'row-active' : ''" @row-click="open">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
          <el-table-column prop="title" label="标题" min-width="200" show-overflow-tooltip />
          <el-table-column prop="risk_score" label="风险" width="80" sortable><template #default="{ row }"><span class="mono">{{ formatRiskScore(row.risk_score) }}</span></template></el-table-column>
          <el-table-column label="状态" width="120"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
          <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template></el-table-column>
        </el-table>
        <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
      </StateBox>
    </div>

    <div class="incident-detail">
      <div v-if="!selected" class="inv-placeholder">选择左侧事件查看攻击链</div>
      <StateBox v-else :loading="detailLoading" :empty="false">
        <template v-if="detail || selected">
          <div class="inv-head">
            <div class="inv-title">安全事件 #{{ (detail || selected)!.id }} · {{ (detail || selected)!.title }}</div>
            <div class="inv-actions">
              <el-select size="small" :model-value="(detail || selected)!.status" style="width: 140px" @change="(v: string) => changeStatus(v)">
                <el-option v-for="s in ['open', 'investigating', 'contained', 'resolved', 'closed']" :key="s" :label="s" :value="s" />
              </el-select>
            </div>
          </div>

          <el-descriptions :column="4" border size="small" class="inv-basic">
            <el-descriptions-item label="等级"><SeverityTag :value="(detail || selected)!.severity" /></el-descriptions-item>
            <el-descriptions-item label="风险评分"><RiskBadge :score="(detail || selected)!.risk_score" /></el-descriptions-item>
            <el-descriptions-item label="置信度"><span class="mono">{{ (((detail || selected)!.confidence) * 100).toFixed(0) }}%</span></el-descriptions-item>
            <el-descriptions-item label="状态"><StatusBadge :value="(detail || selected)!.status" /></el-descriptions-item>
            <el-descriptions-item label="来源"><span class="mono">{{ (detail || selected)!.source || '-' }}</span></el-descriptions-item>
            <el-descriptions-item label="首次出现"><span class="mono">{{ formatDateTime((detail || selected)!.timestamp) }}</span></el-descriptions-item>
            <el-descriptions-item label="最近出现"><span class="mono">{{ formatDateTime((detail || selected)!.last_seen) }}</span></el-descriptions-item>
            <el-descriptions-item label="出现次数">{{ (detail || selected)!.occurrence_count ?? 1 }}</el-descriptions-item>
          </el-descriptions>

          <div class="inv-section">
            <div class="sec-title">攻击链</div>
            <div class="attack-chain">
              <template v-for="(stage, i) in stages" :key="stage.key">
                <div class="chain-node" :class="{ active: activeStages.includes(stage.key) }">
                  <div class="chain-dot" />
                  <span>{{ stage.label }}</span>
                </div>
                <div v-if="i < stages.length - 1" class="chain-arrow" :class="{ active: activeStages.includes(stages[i + 1].key) }" />
              </template>
            </div>
          </div>

          <div class="inv-section">
            <div class="sec-title">关联对象</div>
            <div class="related-grid">
              <div v-if="(detail || selected)!.evidence?.asset" class="related-item" @click="$router.push('/assets')"><span class="ri-type">资产</span><span class="ri-value mono">{{ (detail || selected)!.evidence.asset }}</span></div>
              <div v-if="(detail || selected)!.evidence?.ioc" class="related-item" @click="$router.push('/threat/ioc')"><span class="ri-type">IOC</span><span class="ri-value mono">{{ (detail || selected)!.evidence.ioc }}</span></div>
              <div v-if="(detail || selected)!.evidence?.pcap" class="related-item" @click="$router.push('/network/pcap')"><span class="ri-type">PCAP</span><span class="ri-value">{{ (detail || selected)!.evidence.pcap }}</span></div>
              <div class="related-item"><span class="ri-type">检测</span><span class="ri-value">{{ findings.length }} 项</span></div>
              <div class="related-item" @click="$router.push('/alerts')"><span class="ri-type">告警</span><span class="ri-value">关联告警</span></div>
            </div>
          </div>

          <div class="inv-section">
            <div class="sec-title">关联检测</div>
            <el-table :data="findings" size="small">
              <el-table-column prop="id" label="ID" width="70" />
              <el-table-column prop="engine" label="引擎" width="120" />
              <el-table-column prop="rule_id" label="规则" min-width="140" show-overflow-tooltip />
              <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
              <el-table-column label="风险" width="70"><template #default="{ row }"><span class="mono">{{ formatRiskScore(row.risk_score) }}</span></template></el-table-column>
            </el-table>
          </div>

          <div class="inv-section">
            <div class="sec-title">证据</div>
            <EvidenceViewer :evidence="(detail || selected)!.evidence" />
            <JsonViewer :value="{ incident: detail || selected }" title="完整 JSON 事件" :height="260" />
          </div>
        </template>
      </StateBox>
    </div>

    <el-dialog v-model="correlateOpen" title="手工事件关联" width="720px">
      <el-form label-width="120px">
        <el-form-item label="发现 JSON">
          <el-input v-model="correlateFindings" type="textarea" :rows="10" placeholder='[{"engine":"zeek","rule_id":"A","severity":"High","confidence":0.8,"evidence":{"src_ip":"10.0.0.9"},"timestamp":"2026-01-01T00:00:00Z"}]' />
        </el-form-item>
        <el-form-item label="时间窗口(秒)">
          <el-input-number v-model="correlateWindow" :min="60" :step="60" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="correlateOpen = false">取消</el-button>
        <el-button type="primary" :loading="correlateRunning" @click="runCorrelate">执行关联</el-button>
      </template>

      <div v-if="correlateResult.length" class="correlate-result">
        <div class="sec-title">关联结果（{{ correlateResult.length }}）</div>
        <el-table :data="correlateResult" size="small">
          <el-table-column prop="title" label="标题" min-width="220" show-overflow-tooltip />
          <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
          <el-table-column label="风险" width="90"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
          <el-table-column label="发现数" width="90"><template #default="{ row }"><span class="mono">{{ (row.findings || []).length }}</span></template></el-table-column>
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<style scoped>
.incident-center { display: flex; gap: 12px; height: calc(100vh - var(--soc-header-h) - 32px); }
.correlate-result { margin-top: 12px; border-top: 1px solid var(--soc-border); padding-top: 12px; }
.incident-list { flex: 1; min-width: 0; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; overflow: auto; }
.incident-detail { width: 46%; flex-shrink: 0; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 16px; overflow: auto; }
.inv-placeholder { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--soc-text-dim); }
.inv-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.inv-title { font-size: 16px; font-weight: 700; color: var(--soc-text-strong); }
.inv-actions { display: flex; gap: 8px; }
.inv-basic { margin-bottom: 14px; }
.inv-section { margin-top: 16px; }
.sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
.attack-chain { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.chain-node { display: flex; align-items: center; gap: 6px; padding: 6px 12px; border: 1px solid var(--soc-border); border-radius: 16px; font-size: 12px; color: var(--soc-text-muted); }
.chain-node.active { border-color: var(--soc-primary); color: var(--soc-primary); background: var(--soc-primary-dim); }
.chain-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.chain-arrow { color: var(--soc-text-dim); }
.chain-arrow::before { content: '→'; }
.chain-arrow.active { color: var(--soc-primary); }
.related-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.related-item { border: 1px solid var(--soc-border); border-radius: 6px; padding: 8px; cursor: pointer; }
.related-item:hover { border-color: var(--soc-primary); }
.ri-type { color: var(--soc-text-dim); font-size: 11px; display: block; }
.ri-value { color: var(--soc-text); font-size: 12px; }
:deep(.row-active) td { background: var(--soc-primary-dim) !important; }
</style>
