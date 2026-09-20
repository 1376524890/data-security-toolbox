<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import StateBox from '../../components/common/StateBox.vue'
import StatCard from '../../components/common/StatCard.vue'
import EngineStatusCard from '../../components/security/EngineStatusCard.vue'
import StatusBadge from '../../components/security/StatusBadge.vue'
import SeverityTag from '../../components/security/SeverityTag.vue'
import RiskBadge from '../../components/security/RiskBadge.vue'
import RawViewer from '../../components/evidence/RawViewer.vue'
import { formatDateTime } from '../../utils/format'
import { useEngineDetail } from './composables/useEngineDetail'

const route = useRoute()
const router = useRouter()
const name = computed(() => String(route.params.name || 'zeek'))

// The engine, its rules, its findings and the recent tasks live in the
// composable; this view keeps the route, the navigation and the static labels.
const {
  loading, error, health, tasks, findings, findingsTotal, rules, ruleKeyword, rulePage,
  filteredRules, visibleRules, engineMeta, engineOptions, integration, isSigma, expandRule, load,
} = useEngineDetail(name)

const executionLabels: Record<string, string> = {
  active: '已接入执行', external: '待外部部署', unsupported: '语法不兼容', incomplete: '缺少依赖',
}
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
