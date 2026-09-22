<script setup lang="ts">
/** 安全事件闭环: 资产发现 → 检测发现 → 安全事件 → 告警处置 → 分析报告. */
import { computed } from 'vue'
import ScreenIcon from './ScreenIcon.vue'

const props = defineProps<{ loop: {
  assets: number; findings: number; incidents: number; alerts: number; reports: number
} | null }>()

const steps = computed(() => {
  const loop = props.loop
  if (!loop) return []
  return [
    { key: 'assets', label: '资产发现', value: loop.assets, icon: 'asset', color: '#22d3ee' },
    { key: 'findings', label: '检测发现', value: loop.findings, icon: 'finding', color: '#35a0ff' },
    { key: 'incidents', label: '安全事件', value: loop.incidents, icon: 'event', color: '#f5b638' },
    { key: 'alerts', label: '告警处置', value: loop.alerts, icon: 'alert', color: '#ff4d5e' },
    { key: 'reports', label: '分析报告', value: loop.reports, icon: 'flow', color: '#8b7cff' },
  ]
})
</script>

<template>
  <section class="ds-panel">
    <div class="ds-panel-head"><span class="ds-panel-title">安全事件闭环</span></div>
    <div class="ds-panel-body">
      <template v-if="steps.length">
        <div v-for="(step, index) in steps" :key="step.key" class="ds-loop-step">
          <div class="ds-loop-node" :style="{ color: step.color, borderColor: `${step.color}55` }">
            <ScreenIcon :name="step.icon" :size="16" />
            <span class="ds-loop-value">{{ step.value }}</span>
          </div>
          <div class="ds-loop-label">{{ step.label }}</div>
          <div v-if="index < steps.length - 1" class="ds-loop-arrow" />
        </div>
      </template>
      <div v-else class="ds-empty">闭环数据加载中…</div>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18); background: rgba(11, 30, 54, 0.82);
}
.ds-panel-head { display: flex; align-items: center; justify-content: space-between; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-panel-body { flex: 1; min-height: 0; display: flex; align-items: center; gap: 4px; }
.ds-loop-step { position: relative; flex: 1; text-align: center; }
.ds-loop-node {
  width: 38px; height: 38px; margin: 0 auto; border-radius: 8px; border: 1px solid;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  background: rgba(9, 26, 48, 0.9);
}
.ds-loop-value { font-size: 11px; font-weight: 700; color: #eaf4ff; font-variant-numeric: tabular-nums; }
.ds-loop-label { margin-top: 4px; font-size: 11px; color: #9ec2e6; }
.ds-loop-arrow {
  position: absolute; right: -3px; top: 16px; width: 7px; height: 7px;
  border-top: 1px solid rgba(53, 160, 255, 0.5); border-right: 1px solid rgba(53, 160, 255, 0.5);
  transform: rotate(45deg);
}
.ds-empty { width: 100%; text-align: center; color: #5b7799; font-size: 12px; }
</style>
