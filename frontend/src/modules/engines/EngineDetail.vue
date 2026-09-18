<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { listIntegrations } from '../../api/integrations'
import { getHealth, type HealthResponse } from '../../api/health'
import { getEngineRegistry, type EngineInfo } from '../../api/engine'
import { listTasks } from '../../api/tasks'
import { listDetections } from '../../api/detections'
import { listRules, getRuleContent, type RuleItem } from '../../api/rules'
import type { IntegrationStatus } from '../../types/integration'
import type { Task } from '../../types/task'
import type { DetectionFinding } from '../../types/finding'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import EngineStatusCard, { type EngineStatus } from '../../components/security/EngineStatusCard.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'
import { formatDateTime } from '../../utils/format'

const route = useRoute()
const router = useRouter()
const name = computed(() => String(route.params.name || 'zeek'))
const loading = ref(true)
const error = ref('')
const integrations = ref<IntegrationStatus[]>([])
const health = ref<HealthResponse | null>(null)
const engines = ref<EngineInfo[]>([])
const tasks = ref<Task[]>([])
const findings = ref<DetectionFinding[]>([])
const findingsTotal = ref(0)
const rules = ref<RuleItem[]>([])
const ruleKeyword = ref('')
const rulePage = ref(1)
const filteredRules = computed(() => rules.value.filter(item =>
  `${item.name} ${item.rule_id || ''} ${item.path}`.toLowerCase().includes(ruleKeyword.value.toLowerCase())))
const visibleRules = computed(() => filteredRules.value.slice((rulePage.value - 1) * 30, rulePage.value * 30))
const executionLabels: Record<string, string> = {
  active: '已接入执行', external: '待外部部署', unsupported: '语法不兼容', incomplete: '缺少依赖',
}
async function expandRule(row: RuleItem, expanded: RuleItem[]): Promise<void> {
  if (!expanded.includes(row) || row.content) return
  try { row.content = (await getRuleContent(row)).content }
  catch (err) { error.value = err instanceof Error ? err.message : String(err) }
}
watch(ruleKeyword, () => { rulePage.value = 1 })
watch(name, () => { rulePage.value = 1; void load() })

// ``/engines/sigma`` is a console route while a finding stores the engine's own
// name (``sigma_log_engine``). Resolving the route through the registry is what
// makes the rule count, the rule list and the detection list agree: filtering
// findings by the route name returned nothing for every engine.
const engineMeta = computed(() =>
  engines.value.find((e) => (e.slug || e.name) === name.value || e.name.toLowerCase() === name.value.toLowerCase()),
)
const detectionEngine = computed(() => engineMeta.value?.detection_engine || name.value)
const engineOptions = computed(() =>
  engines.value.map((e) => ({ value: e.slug || e.name, label: `${e.label || e.name} (${e.detection_count ?? 0})` })),
)

// The rule inventory comes from the registry. ``/health`` only reports
// tshark/zeek/suricata, so overriding an adapter's own count with it blanked the
// rule number on every other engine page.
const ruleCount = computed<number | null>(() => {
  if (typeof engineMeta.value?.rule_count === 'number') return engineMeta.value.rule_count
  const adapter = integrations.value.find((i) => i.name.toLowerCase() === name.value.toLowerCase())
  return typeof adapter?.rule_count === 'number' ? adapter.rule_count : null
})

const integration = computed<EngineStatus | null>(() => {
  const item = integrations.value.find((i) => i.name.toLowerCase() === name.value.toLowerCase())
  if (!item) return null
  return { ...item, rule_count: ruleCount.value ?? item.rule_count }
})

const isSigma = computed(() => (engineMeta.value?.name || name.value) === 'sigma_log_engine')

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [ints, h, eng, taskResult] = await Promise.all([
      listIntegrations(),
      getHealth(),
      getEngineRegistry(),
      listTasks({ page: 1, page_size: 20 }),
    ])
    integrations.value = ints
    health.value = h
    engines.value = eng
    tasks.value = taskResult.items
    // Rules and detections are fetched by the engine's own name, which is only
    // known once the registry has answered.
    const [ruleResult, found] = await Promise.all([
      listRules({ engine: detectionEngine.value, include_content: false }),
      listDetections({ engine: detectionEngine.value, page: 1, page_size: 20 }),
    ])
    rules.value = ruleResult.items
    findings.value = found.items
    findingsTotal.value = found.total
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-button @click="router.push('/engines')">← 引擎总览</el-button>
      <el-select :model-value="name" style="width: 240px" filterable @change="(v: string) => router.push(`/engines/${v}`)">
        <el-option v-for="e in engineOptions" :key="e.value" :label="e.label" :value="e.value" />
      </el-select>
      <div class="toolbar-spacer" />
      <el-button @click="load">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="grid cols-3" style="margin-bottom: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />引擎概览</div>
          <EngineStatusCard v-if="integration" :item="integration" />
          <div v-else-if="engineMeta" class="engine-fallback">
            <div class="ef-head">
              <div class="ef-name">{{ engineMeta.label || engineMeta.name }}</div>
              <StatusBadge :value="engineMeta.detection_count ? 'ready' : 'disabled'" />
            </div>
            <div class="ef-row"><span class="ef-label">引擎标识</span><span class="mono">{{ engineMeta.name }}</span></div>
            <div class="ef-row"><span class="ef-label">版本</span><span class="mono">v{{ engineMeta.version || '-' }}</span></div>
            <div class="ef-row"><span class="ef-label">规则数</span><span class="mono">{{ engineMeta.rule_count ?? 0 }}</span></div>
            <div class="ef-row"><span class="ef-label">检测数</span><span class="mono">{{ engineMeta.detection_count ?? 0 }}</span></div>
            <div class="text-dim">平台内置检测引擎，直接读取平台规则库，无独立第三方适配器。</div>
          </div>
          <div v-else class="text-dim">未找到引擎 {{ name }}</div>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot warn" />运行指标</div>
          <div class="run-grid">
            <div class="run-item"><span>分析工作进程</span><StatusBadge :value="health?.analysis_worker || 'offline'" /></div>
            <div class="run-item"><span>tshark</span><StatusBadge :value="health?.tshark?.available ? 'ready' : 'disabled'" /></div>
            <div class="run-item"><span>zeek</span><StatusBadge :value="health?.zeek?.available ? 'ready' : 'disabled'" /></div>
            <div class="run-item"><span>suricata</span><StatusBadge :value="health?.suricata?.available ? 'ready' : 'disabled'" /></div>
          </div>
        </div>
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot danger" />检测结果</div>
          <div class="stat-grid cols-2" style="margin-bottom: 10px">
            <StatCard label="检测" :value="findingsTotal" tone="warning" />
            <StatCard label="任务" :value="tasks.length" tone="info" />
          </div>
          <el-table :data="findings.slice(0, 6)" size="small">
            <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
            <el-table-column prop="rule_id" label="规则" min-width="130" show-overflow-tooltip />
            <el-table-column label="风险" width="80"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
          </el-table>
          <div v-if="!findings.length" class="text-dim">该引擎在当前数据上尚未产生检测结果。</div>
        </div>
      </div>

      <div class="soc-card" style="margin-bottom: 12px">
        <div class="soc-card-title">
          <span class="dot" />{{ isSigma ? 'Sigma 规则清单' : '规则清单' }}（{{ rules.length }}）
        </div>
        <el-input v-model="ruleKeyword" placeholder="搜索规则名称、ID 或路径" clearable style="max-width: 360px; margin-bottom: 12px" />
        <el-table v-if="rules.length" :data="visibleRules" size="small" row-key="path" @expand-change="expandRule">
          <el-table-column type="expand">
            <template #default="{ row }"><RawViewer :value="row.content" :language="row.type === 'yara' ? 'plaintext' : 'yaml'" :height="260" /></template>
          </el-table-column>
          <el-table-column prop="name" label="规则 / 文件" min-width="200" show-overflow-tooltip />
          <el-table-column label="接入状态" width="120"><template #default="{ row }">{{ executionLabels[row.execution] || '待核实' }}</template></el-table-column>
          <el-table-column prop="type" label="类型" width="100"><template #default="{ row }"><StatusBadge :value="row.type" /></template></el-table-column>
          <el-table-column prop="engine" label="生效引擎" width="170" />
          <el-table-column prop="size" label="大小" width="90" />
          <el-table-column prop="path" label="路径" min-width="220" show-overflow-tooltip />
        </el-table>
        <el-pagination v-if="filteredRules.length > 30" v-model:current-page="rulePage" :page-size="30"
          :total="filteredRules.length" layout="total, prev, pager, next" style="margin-top: 12px" />
        <div v-else class="text-dim">该引擎没有平台内置规则文件；适配器型引擎的规则由第三方组件自带规则库提供。</div>
      </div>

      <div class="soc-card">
        <div class="soc-card-title"><span class="dot" />最近任务</div>
        <el-table :data="tasks" size="small">
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="kind" label="类型" width="110" />
          <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
          <el-table-column prop="current_stage" label="阶段" min-width="160" />
          <el-table-column prop="progress" label="进度" width="80" />
          <el-table-column label="时间" width="150"><template #default="{ row }">{{ formatDateTime(row.created_at) }}</template></el-table-column>
        </el-table>
      </div>
    </StateBox>
  </div>
</template>

<style scoped>
.run-grid { display: flex; flex-direction: column; gap: 8px; }
.run-item { display: flex; align-items: center; justify-content: space-between; padding: 6px 0; border-bottom: 1px dashed var(--soc-border); color: var(--soc-text-muted); }
.engine-fallback { display: flex; flex-direction: column; gap: 6px; }
.ef-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
.ef-name { font-size: 16px; font-weight: 700; color: var(--soc-text-strong); }
.ef-row { display: flex; justify-content: space-between; color: var(--soc-text-muted); font-size: 12px; }
.ef-label { color: var(--soc-text-dim); }
</style>
