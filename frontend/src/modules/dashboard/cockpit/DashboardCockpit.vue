<script setup lang="ts">
/**
 * 数据安全综合驾驶舱 — the console's daily-use homepage.
 *
 * The page lives inside the console shell (sidebar and header stay), and every
 * figure on it comes from ``useDashboardCockpit``: the wall screen is the other
 * homepage (``/``, no shell) and both read the same aggregate, so the two pages
 * can never disagree about a number.
 *
 * The view owns layout, routing and formatting only.
 */
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { formatDateTime } from '../../../utils/format'
import CockpitCard from './components/CockpitCard.vue'
import OverviewCards from './components/OverviewCards.vue'
import HealthScore from './components/HealthScore.vue'
import WeeklyFocus from './components/WeeklyFocus.vue'
import SystemStatus from './components/SystemStatus.vue'
import AssetDistribution from './components/AssetDistribution.vue'
import RiskDistribution from './components/RiskDistribution.vue'
import ComplianceProgress from './components/ComplianceProgress.vue'
import DataFlowSummary from './components/DataFlowSummary.vue'
import SecurityPipeline from './components/SecurityPipeline.vue'
import RecentTasks from './components/RecentTasks.vue'
import {
  useDashboardCockpit, type CockpitMetric, type CockpitRange, type FocusItem,
  type PipelineStep,
} from './composables/useDashboardCockpit'

const router = useRouter()
const {
  loading, error, stale, updatedAt, range, refresh, setRange,
  metrics, health, healthNote, focus, status, compliance,
  riskSlices, riskTotal, assetTabs, pipeline, taskRows, trend, flowTotals, flowWeekly,
} = useDashboardCockpit()

const updatedText = computed(() =>
  updatedAt.value ? formatDateTime(updatedAt.value.toISOString()) : '')

function go(route: string): void {
  if (route) router.push(route)
}
function openMetric(item: CockpitMetric): void { go(item.route) }
function openFocus(item: FocusItem): void { go(item.route) }
function openStep(step: PipelineStep): void { go(step.route) }
function openTasks(): void { router.push('/tasks') }
function onRange(value: CockpitRange): void { setRange(value) }
</script>

<template>
  <div class="ck-page">
    <!-- A failed refresh keeps the last good numbers on screen; this banner says
         they are old instead of blanking the page. -->
    <div v-if="stale" class="ck-stale">
      <el-icon><WarningFilled /></el-icon>
      <span>数据刷新失败：{{ error }}（下方为最近一次成功的数据）</span>
      <button type="button" class="ck-stale-action" @click="refresh">重试</button>
    </div>

    <div class="ck-toolbar">
      <span class="ck-toolbar-hint">企业数据安全整体状态 · 资产 / 风险 / 事件 / 告警 / 流动 / 合规</span>
      <span class="ck-toolbar-spacer" />
      <span v-if="updatedText" class="ck-toolbar-time">最近更新 {{ updatedText }}</span>
      <button type="button" class="ck-refresh" :disabled="loading" @click="refresh">
        <el-icon :class="{ spin: loading }"><Refresh /></el-icon>刷新
      </button>
    </div>

    <OverviewCards :items="metrics" @open="openMetric" />

    <div class="ck-grid ck-row-health">
      <CockpitCard title="数据安全健康度" class="ck-cell">
        <HealthScore :health="health" :note="healthNote" @open="go('/data-assets')" />
      </CockpitCard>
      <CockpitCard title="本周重点关注" action="更多" class="ck-cell" @action="go('/data-assets')">
        <WeeklyFocus :items="focus" @open="openFocus" />
      </CockpitCard>
      <CockpitCard title="探针与引擎状态" action="更多" class="ck-cell"
                   @action="go('/collection-rules')">
        <SystemStatus :items="status" />
      </CockpitCard>
    </div>

    <div class="ck-grid ck-row-dist">
      <AssetDistribution :tabs="assetTabs" />
      <RiskDistribution :slices="riskSlices" :total="riskTotal" />
      <ComplianceProgress :board="compliance" @open="go('/collection-rules')" />
      <DataFlowSummary :trend="trend" :totals="flowTotals" :weekly="flowWeekly" :range="range"
                       @range="onRange" @open="go('/network/dlp')" />
    </div>

    <div class="ck-grid ck-row-bottom">
      <SecurityPipeline :steps="pipeline" @open="openStep" />
      <RecentTasks :rows="taskRows" @open="openTasks" />
    </div>
  </div>
</template>

<style scoped>
.ck-page { display: flex; flex-direction: column; gap: 12px; min-width: 0; }

.ck-stale {
  display: flex; align-items: center; gap: 8px; font-size: 12px;
  padding: 8px 12px; border-radius: 8px; color: var(--soc-warning);
  border: 1px solid var(--soc-warning); background: rgba(245, 158, 11, 0.08);
}
.ck-stale-action {
  margin-left: auto; border: 0; background: none; cursor: pointer; font: inherit;
  color: inherit; text-decoration: underline;
}

.ck-toolbar { display: flex; align-items: center; gap: 10px; min-height: 24px; }
.ck-toolbar-hint { font-size: 12px; color: var(--soc-text-muted); }
.ck-toolbar-spacer { flex: 1; }
.ck-toolbar-time { font-size: 12px; color: var(--soc-text-dim); }
.ck-refresh {
  display: inline-flex; align-items: center; gap: 4px; cursor: pointer; font: inherit;
  font-size: 12px; color: var(--soc-text-muted); background: var(--soc-panel);
  border: 1px solid var(--soc-border); border-radius: 6px; padding: 3px 10px;
}
.ck-refresh:hover { color: var(--soc-primary); border-color: var(--soc-primary); }
.ck-refresh:disabled { cursor: default; opacity: 0.7; }
.spin { animation: ck-spin 1s linear infinite; }
@keyframes ck-spin { to { transform: rotate(360deg); } }

.ck-grid { display: grid; gap: 12px; min-width: 0; }
.ck-row-health { grid-template-columns: 5fr 4fr 3fr; }
.ck-row-dist { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.ck-row-bottom { grid-template-columns: 7fr 5fr; }
.ck-cell { min-width: 0; }

/* Below the reference width the three rows fold, never squashing a ring. */
@media (max-width: 1600px) {
  .ck-row-dist { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
/* Below this the third health card only has room for a vertical label, so the
   row folds into two columns instead of squeezing 探针与引擎状态. */
@media (max-width: 1500px) {
  .ck-row-health { grid-template-columns: 1fr 1fr; }
  .ck-row-bottom { grid-template-columns: 1fr; }
}
@media (max-width: 1100px) {
  .ck-row-health, .ck-row-dist { grid-template-columns: 1fr; }
}

:deep(.el-icon) { vertical-align: middle; }
</style>
