<script setup lang="ts">
/**
 * 数据安全闭环流程: 资产发现 → 安全发现 → 安全事件 → 告警处置 → 分析报告.
 *
 * The five counts are the same totals the KPI band shows (assets, findings,
 * incidents, alerts) plus the report count, taken from one overview response -
 * the pipeline is a picture of the loop, not a second tally.
 */
import CockpitCard from './CockpitCard.vue'
import type { PipelineStep } from '../composables/useDashboardCockpit'

defineProps<{ steps: PipelineStep[] }>()
defineEmits<{ open: [step: PipelineStep] }>()
</script>

<template>
  <CockpitCard title="数据安全闭环流程">
    <ol class="sp">
      <li v-for="(step, index) in steps" :key="step.key">
        <!-- A stage with no console page is drawn but not clickable, rather
             than linking somewhere that only looks like the same thing. -->
        <component :is="step.route ? 'button' : 'div'" class="sp-node"
                   :class="{ clickable: Boolean(step.route) }"
                   v-bind="step.route ? { type: 'button' } : {}"
                   @click="step.route && $emit('open', step)">
          <span class="sp-icon" :style="{ background: `${step.color}14`, color: step.color }">
            <el-icon :size="20"><component :is="step.icon" /></el-icon>
          </span>
          <span class="sp-label">{{ step.label }}</span>
          <span class="sp-value">{{ step.value.toLocaleString('zh-CN') }}</span>
          <span class="sp-unit">{{ step.caption }}</span>
        </component>
        <span v-if="index < steps.length - 1" class="sp-arrow">›</span>
      </li>
    </ol>
  </CockpitCard>
</template>

<style scoped>
.sp { list-style: none; margin: 0; padding: 0; display: flex; align-items: stretch; }
.sp li { display: flex; align-items: center; flex: 1; min-width: 0; }
.sp-node {
  flex: 1; min-width: 0; display: flex; flex-direction: column; align-items: center; gap: 4px;
  padding: 12px 8px; border: 1px solid var(--soc-border); border-radius: 8px;
  background: var(--soc-panel-2, transparent); font: inherit; color: inherit;
  transition: border-color 0.15s ease, transform 0.15s ease;
}
.sp-node.clickable { cursor: pointer; }
.sp-node.clickable:hover { border-color: var(--soc-primary); transform: translateY(-1px); }
.sp-icon {
  width: 34px; height: 34px; border-radius: 10px; display: inline-flex;
  align-items: center; justify-content: center;
}
.sp-label { font-size: 12px; color: var(--soc-text-muted); }
.sp-value {
  font-size: 20px; font-weight: 700; color: var(--soc-text-strong);
  font-variant-numeric: tabular-nums; line-height: 1.2;
}
.sp-unit { font-size: 11px; color: var(--soc-text-dim); }
.sp-arrow {
  flex-shrink: 0; padding: 0 6px; color: var(--soc-border-2); font-size: 20px; line-height: 1;
}
@media (max-width: 1400px) {
  .sp-unit { display: none; }
}
</style>
