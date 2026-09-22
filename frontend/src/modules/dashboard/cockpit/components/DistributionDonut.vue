<script setup lang="ts">
/**
 * Ring + centre total + legend, shared by 资产分布 and 风险等级分布.
 *
 * The two cards differ only in their slices and their tab strip, so the drawing
 * lives here once. Percentages are shares of the slices actually drawn (the
 * server sends one row per category, so the denominator is the whole group),
 * never of a total handed in from elsewhere.
 */
import { computed } from 'vue'
import BaseChart from '../../../../components/charts/BaseChart.vue'
import { donutOption } from '../chartTheme'
import type { DonutSlice } from '../composables/useDashboardCockpit'

const props = defineProps<{
  slices: DonutSlice[]
  total: number
  totalLabel: string
  height?: number
}>()

const option = computed(() => donutOption(props.slices))
const sum = computed(() => props.slices.reduce((acc, item) => acc + Number(item.value || 0), 0))

function share(value: number): string {
  if (!sum.value) return '—'
  return `${((value * 100) / sum.value).toFixed(1)}%`
}
const totalText = computed(() =>
  props.slices.length ? Number(props.total || 0).toLocaleString('zh-CN') : '—')
</script>

<template>
  <div class="dd">
    <div class="dd-ring">
      <BaseChart :option="option" :height="height || 172" />
      <div class="dd-center">
        <div class="dd-total">{{ totalText }}</div>
        <div class="dd-label">{{ totalLabel }}</div>
      </div>
    </div>
    <ul class="dd-legend">
      <li v-for="item in slices" :key="item.name">
        <span class="dd-dot" :style="{ background: item.color }" />
        <span class="dd-name" :title="item.name">{{ item.name }}</span>
        <span class="dd-value">{{ item.value.toLocaleString('zh-CN') }}</span>
        <span class="dd-share">{{ share(item.value) }}</span>
      </li>
      <li v-if="!slices.length" class="dd-empty">暂无数据</li>
    </ul>
  </div>
</template>

<style scoped>
.dd { display: flex; align-items: center; gap: 14px; }
.dd-ring { position: relative; width: 176px; flex-shrink: 0; }
.dd-center {
  position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%);
  text-align: center; pointer-events: none;
}
.dd-total {
  font-size: 24px; font-weight: 700; color: var(--soc-text-strong); line-height: 1.15;
  font-variant-numeric: tabular-nums;
}
.dd-label { font-size: 11px; color: var(--soc-text-muted); margin-top: 2px; }
.dd-legend {
  list-style: none; margin: 0; padding: 0; flex: 1; min-width: 0;
  display: flex; flex-direction: column; gap: 7px;
}
.dd-legend li {
  display: grid; grid-template-columns: 8px 1fr auto 46px;
  align-items: center; gap: 8px; font-size: 12px;
}
.dd-dot { width: 8px; height: 8px; border-radius: 2px; }
.dd-name { color: var(--soc-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dd-value { font-weight: 700; color: var(--soc-text-strong); font-variant-numeric: tabular-nums; }
.dd-share { text-align: right; color: var(--soc-text-muted); font-variant-numeric: tabular-nums; }
.dd-empty { grid-template-columns: 1fr; color: var(--soc-text-dim); }
</style>
