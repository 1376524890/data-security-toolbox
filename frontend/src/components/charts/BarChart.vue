<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'

const props = defineProps<{
  xData: string[]
  data: number[]
  color?: string
  horizontal?: boolean
  height?: number | string
}>()

const option = computed<echarts.EChartsOption>(() => ({
  tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
  grid: { left: 44, right: 20, top: 24, bottom: 30 },
  xAxis: props.horizontal ? { type: 'value', splitLine: { lineStyle: { color: '#1f2937' } }, axisLabel: { color: '#9ca3af' } } : { type: 'category', data: props.xData, axisLabel: { color: '#9ca3af' }, axisLine: { lineStyle: { color: '#1f2937' } } },
  yAxis: props.horizontal ? { type: 'category', data: props.xData, axisLabel: { color: '#9ca3af' } } : { type: 'value', splitLine: { lineStyle: { color: '#1f2937' } }, axisLabel: { color: '#9ca3af' } },
  series: [{ type: 'bar', data: props.data, itemStyle: { color: props.color || '#38bdf8', borderRadius: 2 }, barWidth: '55%' }],
}))
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
