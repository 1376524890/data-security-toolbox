<script setup lang="ts">
import { onMounted, reactive, ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { listAlerts, getAlert, updateAlert, getAlertSummary, type AlertQuery } from '../../../api/alerts'
import type { Alert, AlertDetail, AlertSummary } from '../../../types/alert'
import StateBox from '../../../components/common/StateBox.vue'
import FilterBar, { type FilterField } from '../../../components/common/FilterBar.vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import StatusBadge from '../../../components/security/StatusBadge.vue'
import RiskBadge from '../../../components/security/RiskBadge.vue'
import EvidenceViewer from '../../../components/evidence/EvidenceViewer.vue'
import JsonViewer from '../../../components/evidence/JsonViewer.vue'
import Timeline from '../../../components/common/Timeline.vue'
import { formatDateTime } from '../../../utils/format'

const loading = ref(true)
const error = ref('')
const items = ref<Alert[]>([])
const total = ref(0)
const selected = ref<Alert | null>(null)
const detail = ref<AlertDetail | null>(null)
const detailLoading = ref(false)
const summary = ref<AlertSummary | null>(null)
const filters = reactive<AlertQuery>({ search: '', status: '', severity: '', page: 1, page_size: 50 })

const filterFields: FilterField[] = [
  { key: 'search', label: '搜索标题/摘要', placeholder: '搜索标题 / 摘要 / 指纹', width: '240px' },
  { key: 'severity', label: '等级', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'].map((v) => ({ label: v, value: v })), width: '120px' },
  { key: 'status', label: '状态', type: 'select', options: ['new', 'acknowledged', 'resolved', 'suppressed'].map((v) => ({ label: v, value: v })), width: '140px' },
]

const confidence = computed(() => detail.value?.finding?.confidence)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [result, sum] = await Promise.all([listAlerts({ ...filters }), getAlertSummary()])
    items.value = result.items
    total.value = result.total
    summary.value = sum
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

async function open(row: Alert): Promise<void> {
  selected.value = row
  detailLoading.value = true
  try {
    detail.value = await getAlert(row.id)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  } finally {
    detailLoading.value = false
  }
}

async function changeStatus(status: string): Promise<void> {
  if (!selected.value) return
  try {
    await updateAlert(selected.value.id, { status })
    ElMessage.success(`已标记为 ${status}`)
    await open(selected.value)
    await load()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : String(err))
  }
}

function reset(): void { filters.page = 1; load() }

onMounted(load)
</script>

<template>
  <div class="alert-center">
    <div class="alert-list">
      <div class="list-head">
        <FilterBar :filters="filterFields" :model="filters" @search="reset" @reset="reset" />
        <div class="list-summary">
          <span class="text-muted">共 {{ total }}</span>
          <template v-if="summary">
            <span class="pill critical">{{ summary.severity?.Critical || 0 }} Critical</span>
            <span class="pill high">{{ summary.severity?.High || 0 }} High</span>
            <span class="pill unhandled">{{ summary.unhandled_critical_high || 0 }} 未处理高危</span>
          </template>
        </div>
      </div>
      <StateBox :loading="loading" :error="error" :empty="!items.length" @retry="load">
        <div class="list-body">
          <div v-for="row in items" :key="row.id" class="alert-row" :class="{ active: selected?.id === row.id }" @click="open(row)">
            <div class="ar-top">
              <SeverityTag :value="row.severity" />
              <span class="ar-score mono">{{ row.risk_score }}</span>
              <StatusBadge :value="row.status" />
            </div>
            <div class="ar-title">{{ row.title }}</div>
            <div class="ar-meta">
              <span class="mono">{{ row.source }}</span>
              <span class="text-dim">{{ formatDateTime(row.last_seen) }}</span>
              <span class="text-dim">x{{ row.occurrence_count }}</span>
            </div>
          </div>
        </div>
        <el-pagination class="pagination" layout="total, prev, pager, next" :total="total" :page-size="filters.page_size" :current-page="filters.page" @current-change="(p: number) => { filters.page = p; load() }" />
      </StateBox>
    </div>

    <div class="alert-investigation">
      <div v-if="!selected" class="inv-placeholder">选择左侧告警开始调查</div>
      <StateBox v-else :loading="detailLoading" :empty="false">
        <template v-if="detail">
          <div class="inv-head">
            <div class="inv-title">告警 #{{ detail.alert.id }}</div>
            <div class="inv-actions">
              <el-button size="small" type="primary" @click="changeStatus('acknowledged')">确认</el-button>
              <el-button size="small" type="success" @click="changeStatus('resolved')">解决</el-button>
              <el-button size="small" type="warning" @click="changeStatus('suppressed')">抑制</el-button>
            </div>
          </div>

          <el-descriptions :column="4" border size="small" class="inv-basic">
            <el-descriptions-item label="告警 ID"><span class="mono">{{ detail.alert.id }}</span></el-descriptions-item>
            <el-descriptions-item label="指纹"><span class="mono">{{ detail.alert.fingerprint }}</span></el-descriptions-item>
            <el-descriptions-item label="等级"><SeverityTag :value="detail.alert.severity" /></el-descriptions-item>
            <el-descriptions-item label="风险评分"><RiskBadge :score="detail.alert.risk_score" /></el-descriptions-item>
            <el-descriptions-item label="置信度"><span class="mono">{{ confidence != null ? (confidence * 100).toFixed(0) + '%' : '-' }}</span></el-descriptions-item>
            <el-descriptions-item label="创建时间"><span class="mono">{{ formatDateTime(detail.alert.created_at) }}</span></el-descriptions-item>
            <el-descriptions-item label="最近出现"><span class="mono">{{ formatDateTime(detail.alert.last_seen) }}</span></el-descriptions-item>
            <el-descriptions-item label="出现次数">{{ detail.alert.occurrence_count }}</el-descriptions-item>
          </el-descriptions>

          <div class="inv-sections">
            <div class="inv-section">
              <div class="sec-title">检测来源</div>
              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="引擎">{{ detail.finding?.engine || detail.alert.source || '-' }}</el-descriptions-item>
                <el-descriptions-item label="规则 ID"><span class="mono">{{ detail.finding?.rule_id || '-' }}</span></el-descriptions-item>
                <el-descriptions-item label="目标">{{ detail.finding?.target_type }} / {{ detail.finding?.target_id }}</el-descriptions-item>
                <el-descriptions-item label="处置建议">{{ detail.finding?.recommendation || '-' }}</el-descriptions-item>
              </el-descriptions>
            </div>

            <div class="inv-section">
              <div class="sec-title">MITRE ATT&CK</div>
              <div class="attack-row">
                <span class="text-muted">战术</span><span class="mono">{{ detail.finding?.evidence?.tactic || '-' }}</span>
                <span class="text-muted">技术</span><span class="mono">{{ detail.finding?.evidence?.technique || '-' }}</span>
                <span class="text-muted">ID</span><span class="mono">{{ detail.finding?.evidence?.technique_id || '-' }}</span>
              </div>
            </div>

            <div class="inv-section">
              <div class="sec-title">关联对象</div>
              <div class="related-grid">
                <div v-if="detail.finding" class="related-item" @click="$router.push('/detections')"><span class="ri-type">检测</span><span class="ri-value mono">#{{ detail.finding.id }} · {{ detail.finding.engine }}</span></div>
                <div v-if="detail.incident" class="related-item" @click="$router.push('/incidents')"><span class="ri-type">事件</span><span class="ri-value">#{{ detail.incident.id }} · {{ detail.incident.title }}</span></div>
                <div v-if="detail.probe" class="related-item"><span class="ri-type">探针</span><span class="ri-value">{{ detail.probe.name }}</span></div>
                <div v-if="detail.pcap" class="related-item" @click="$router.push('/network/pcap')"><span class="ri-type">PCAP</span><span class="ri-value">{{ detail.pcap.filename }}</span></div>
                <div v-if="detail.finding?.evidence?.ip" class="related-item" @click="$router.push('/assets')"><span class="ri-type">资产</span><span class="ri-value mono">{{ detail.finding.evidence.ip }}</span></div>
                <div v-if="detail.finding?.evidence?.value" class="related-item" @click="$router.push('/threat/ioc')"><span class="ri-type">IOC</span><span class="ri-value mono">{{ detail.finding.evidence.value }}</span></div>
              </div>
            </div>

            <div class="inv-section">
              <div class="sec-title">攻击时间线</div>
              <Timeline :items="[
                { time: formatDateTime(detail.alert.created_at), title: '告警创建', status: 'info' },
                { time: formatDateTime(detail.alert.last_seen), title: '最近出现', description: `第 ${detail.alert.occurrence_count} 次`, status: 'warning' },
                ...detail.deliveries.map((d) => ({ time: formatDateTime(d.sent_at), title: `${d.channel} → ${d.target}`, description: d.status, status: d.status === 'success' ? 'success' : 'danger' })),
              ]" />
            </div>

            <div class="inv-section">
              <div class="sec-title">证据</div>
              <EvidenceViewer :evidence="detail.finding?.evidence" />
              <JsonViewer :value="{ finding: detail.finding, incident: detail.incident, pcap: detail.pcap, probe: detail.probe }" title="完整 JSON 证据" :height="260" />
            </div>
          </div>
        </template>
      </StateBox>
    </div>
  </div>
</template>

<style scoped>
.alert-center { display: flex; gap: 12px; height: calc(100vh - var(--soc-header-h) - 32px); }
.alert-list { width: 420px; flex-shrink: 0; display: flex; flex-direction: column; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 12px; }
.list-head { display: flex; flex-direction: column; gap: 8px; }
.list-summary { display: flex; gap: 8px; align-items: center; }
.pill { padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.pill.critical { background: rgba(239,68,68,0.15); color: #ef4444; }
.pill.high { background: rgba(249,115,22,0.15); color: #f97316; }
.pill.unhandled { background: rgba(234,179,8,0.15); color: #eab308; }
.list-body { flex: 1; overflow: auto; }
.alert-row { padding: 10px; border: 1px solid transparent; border-radius: 6px; cursor: pointer; margin-bottom: 4px; }
.alert-row:hover { background: var(--soc-panel-hover); }
.alert-row.active { border-color: var(--soc-primary); background: var(--soc-primary-dim); }
.ar-top { display: flex; align-items: center; gap: 8px; }
.ar-score { margin-left: auto; font-weight: 700; }
.ar-title { font-weight: 600; color: var(--soc-text-strong); margin-top: 6px; font-size: 13px; }
.ar-meta { display: flex; gap: 10px; color: var(--soc-text-dim); font-size: 11px; margin-top: 4px; }
.alert-investigation { flex: 1; min-width: 0; background: var(--soc-panel); border: 1px solid var(--soc-border); border-radius: var(--soc-radius); padding: 16px; overflow: auto; }
.inv-placeholder { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--soc-text-dim); }
.inv-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.inv-title { font-size: 16px; font-weight: 700; color: var(--soc-text-strong); }
.inv-actions { display: flex; gap: 8px; }
.inv-basic { margin-bottom: 14px; }
.inv-sections { display: flex; flex-direction: column; gap: 16px; }
.inv-section .sec-title { font-size: 12px; font-weight: 700; color: var(--soc-primary); margin-bottom: 8px; }
.attack-row { display: grid; grid-template-columns: 80px 1fr 80px 1fr 40px 1fr; gap: 6px; align-items: center; font-size: 12px; }
.related-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.related-item { border: 1px solid var(--soc-border); border-radius: 6px; padding: 8px; cursor: pointer; }
.related-item:hover { border-color: var(--soc-primary); }
.ri-type { color: var(--soc-text-dim); font-size: 11px; display: block; }
.ri-value { color: var(--soc-text); font-size: 12px; }
</style>
