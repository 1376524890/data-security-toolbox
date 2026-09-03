<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { listIntegrations } from '../../api/integrations'
import { getHealth, type HealthResponse } from '../../api/health'
import { getEngineRegistry, type EngineInfo } from '../../api/engine'
import { listTasks } from '../../api/tasks'
import { listDetections } from '../../api/detections'
import { listOfflineResources } from '../../api/offline'
import type { IntegrationStatus } from '../../types/integration'
import type { Task } from '../../types/task'
import type { DetectionFinding } from '../../types/finding'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import EngineStatusCard, { type EngineStatus } from '../../components/security/EngineStatusCard.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
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
const resources = ref<Array<{ resource_type: string; name: string; version: string; count: number; status: string }>>([])

const integration = computed<EngineStatus | null>(() => {
  const item = integrations.value.find((i) => i.name.toLowerCase() === name.value.toLowerCase())
  if (!item) return null
  return { ...item, rule_count: (health.value as any)?.[name.value]?.rule_count }
})

const engineMeta = computed(() => engines.value.find((e) => e.name.toLowerCase() === name.value.toLowerCase()))
const isSigma = computed(() => name.value.toLowerCase() === 'sigma')

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [ints, h, eng, taskResult, findingResult, res] = await Promise.all([
      listIntegrations(),
      getHealth(),
      getEngineRegistry(),
      listTasks({ page: 1, page_size: 20 }),
      listDetections({ engine: name.value, page: 1, page_size: 20 }),
      listOfflineResources(),
    ])
    integrations.value = ints
    health.value = h
    engines.value = eng
    tasks.value = taskResult.items
    findings.value = findingResult.items
    resources.value = res
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

const sigmaResources = computed(() => resources.value.filter((r) => r.resource_type === 'sigma_rules'))
const engineNames = ['zeek', 'suricata', 'sigma', 'wazuh', 'osquery', 'openscap']

onMounted(load)
</script>

<template>
  <div>
    <div class="toolbar">
      <el-select :model-value="name" style="width: 180px" @change="(v: string) => router.push(`/engines/${v}`)">
        <el-option v-for="e in engineNames" :key="e" :label="e" :value="e" />
      </el-select>
      <div class="toolbar-spacer" />
      <el-button @click="load">刷新</el-button>
    </div>
    <StateBox :loading="loading" :error="error" :empty="false" @retry="load">
      <div class="grid cols-3" style="margin-bottom: 12px">
        <div class="soc-card">
          <div class="soc-card-title"><span class="dot" />引擎概览</div>
          <EngineStatusCard v-if="integration" :item="integration" />
          <div v-else class="text-dim">
            {{ isSigma ? 'Sigma 为内置规则解释器，无独立适配器；规则资源如下' : `未找到 ${name} 适配器` }}
            <div v-if="engineMeta" class="text-dim">{{ engineMeta.name }} v{{ engineMeta.version }}</div>
          </div>
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
            <StatCard label="检测" :value="findings.length" tone="warning" />
            <StatCard label="任务" :value="tasks.length" tone="info" />
          </div>
          <el-table :data="findings.slice(0, 6)" size="small">
            <el-table-column label="等级" width="90"><template #default="{ row }"><SeverityTag :value="row.severity" /></template></el-table-column>
            <el-table-column prop="rule_id" label="规则" min-width="130" show-overflow-tooltip />
            <el-table-column label="风险" width="80"><template #default="{ row }"><RiskBadge :score="row.risk_score" /></template></el-table-column>
          </el-table>
        </div>
      </div>

      <div v-if="isSigma" class="soc-card" style="margin-bottom: 12px">
        <div class="soc-card-title"><span class="dot" />Sigma 规则资源</div>
        <el-table :data="sigmaResources" size="small">
          <el-table-column prop="name" label="名称" min-width="160" />
          <el-table-column prop="version" label="版本" width="100" />
          <el-table-column prop="count" label="规则数" width="90" />
          <el-table-column label="状态" width="100"><template #default="{ row }"><StatusBadge :value="row.status" /></template></el-table-column>
        </el-table>
        <div v-if="!sigmaResources.length" class="text-dim">暂无 Sigma 规则资源</div>
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
</style>
