<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'

const props = defineProps<{
  xData: string[]
  series: Array<{ name: string; data: number[]; color?: string; area?: boolean }>
  height?: number | string
}>()

const option = computed<echarts.EChartsOption>(() => ({
  tooltip: { trigger: 'axis' },
  legend: { textStyle: { color: '#9ca3af' }, top: 0 },
  grid: { left: 44, right: 20, top: 32, bottom: 30 },
  xAxis: { type: 'category', data: props.xData, axisLine: { lineStyle: { color: '#1f2937' } }, axisLabel: { color: '#9ca3af' } },
  yAxis: { type: 'value', splitLine: { lineStyle: { color: '#1f2937' } }, axisLabel: { color: '#9ca3af' } },
  series: props.series.map((s) => ({
    name: s.name,
    type: 'line',
    smooth: true,
    showSymbol: false,
    data: s.data,
    itemStyle: { color: s.color },
    lineStyle: { color: s.color, width: 2 },
    areaStyle: s.area ? { color: s.color, opacity: 0.08 } : undefined,
  })),
}))
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
