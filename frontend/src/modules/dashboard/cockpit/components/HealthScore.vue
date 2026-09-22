<script setup lang="ts">
/**
 * 数据安全健康度: the ring, the four sub-scores and the arithmetic behind them.
 *
 * The score comes from the server (the page never computes it); this component
 * only renders it and the numerator/denominator each dimension was scored on.
 */
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from '../../../../components/charts/BaseChart.vue'
import type { HealthScore } from '../../../../types/dashboard'
import { cockpitColors } from '../chartTheme'
import { chartColors, themeMode } from '../../../../utils/theme'

const props = defineProps<{ health: HealthScore | null; note: string }>()
defineEmits<{ open: [] }>()

const score = computed(() => props.health?.score ?? null)
const grade = computed(() => props.health?.grade || '')
const components = computed(() => props.health?.components || [])

function bandColor(value: number | null): string {
  if (value === null) return cockpitColors.slate
  if (value >= 85) return cockpitColors.green
  if (value >= 70) return cockpitColors.blue
  if (value >= 60) return cockpitColors.amber
  return cockpitColors.red
}
const ringColor = computed(() => bandColor(score.value))

const ring = computed<echarts.EChartsOption>(() => {
  themeMode.value
  const colors = chartColors()
  return {
    series: [{
      type: 'gauge',
      startAngle: 220,
      endAngle: -40,
      min: 0,
      max: 100,
      radius: '100%',
      center: ['50%', '58%'],
      progress: { show: true, width: 14, roundCap: true, itemStyle: { color: ringColor.value } },
      axisLine: { lineStyle: { width: 14, color: [[1, colors.grid]] } },
      pointer: { show: false },
      axisTick: { show: false },
      splitLine: { show: false },
      axisLabel: { show: false },
      detail: { show: false },
      data: [{ value: score.value ?? 0 }],
      silent: true,
    }],
  }
})

function bar(item: { score: number | null }): string {
  return `${Math.max(0, Math.min(100, item.score ?? 0))}%`
}
function value(item: { score: number | null }): string {
  return item.score === null ? '—' : item.score.toFixed(1)
}
</script>

<template>
  <div class="hs">
    <div class="hs-ring">
      <BaseChart :option="ring" height="156px" />
      <div class="hs-center">
        <div class="hs-score">{{ score === null ? '—' : score.toFixed(1) }}</div>
        <div class="hs-grade">{{ grade || '待评估' }}</div>
      </div>
    </div>
    <div class="hs-body">
      <div class="hs-note">{{ note }}</div>
      <ul class="hs-list">
        <li v-for="item in components" :key="item.key">
          <span class="hs-label">{{ item.label }}</span>
          <span class="hs-track">
            <i :style="{ width: bar(item), background: bandColor(item.score) }" />
          </span>
          <span class="hs-value" :style="{ color: bandColor(item.score) }">{{ value(item) }}</span>
        </li>
      </ul>
      <button type="button" class="hs-more" @click="$emit('open')">查看详情</button>
    </div>
  </div>
</template>

<style scoped>
.hs { display: flex; align-items: center; gap: 18px; }
.hs-ring { position: relative; width: 176px; flex-shrink: 0; }
.hs-center {
  position: absolute; left: 50%; top: 58%; transform: translate(-50%, -50%);
  text-align: center; pointer-events: none;
}
.hs-score {
  font-size: 30px; font-weight: 700; line-height: 1.1; color: var(--soc-text-strong);
  font-variant-numeric: tabular-nums;
}
.hs-grade { font-size: 12px; color: var(--soc-primary); font-weight: 600; }
.hs-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 10px; }
.hs-note { font-size: 12px; line-height: 1.7; color: var(--soc-text-muted); }
.hs-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.hs-list li { display: grid; grid-template-columns: 62px 1fr 40px; align-items: center; gap: 10px; }
.hs-label { font-size: 12px; color: var(--soc-text); }
.hs-track { height: 6px; border-radius: 3px; background: var(--soc-panel-hover); overflow: hidden; }
.hs-track i { display: block; height: 100%; border-radius: 3px; transition: width 0.3s ease; }
.hs-value { font-size: 12px; font-weight: 700; text-align: right; font-variant-numeric: tabular-nums; }
.hs-more {
  align-self: flex-start; margin-top: 2px; padding: 5px 14px; cursor: pointer;
  font-size: 12px; border-radius: 6px; border: 1px solid var(--soc-primary);
  color: var(--soc-primary); background: var(--soc-primary-dim);
}
.hs-more:hover { background: var(--soc-primary); color: #fff; }
</style>
