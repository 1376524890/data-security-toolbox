<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'
import { chartColors, themeMode } from '../../utils/theme'

const props = defineProps<{
  xData: string[]
  data: number[]
  color?: string
  horizontal?: boolean
  height?: number | string
}>()

const option = computed<echarts.EChartsOption>(() => {
  // Rebuilt on a theme switch: the grid and axis colours are tokens now, and an
  // ECharts option keeps whatever literals it was built with.
  themeMode.value
  const colors = chartColors()
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 44, right: 20, top: 24, bottom: 30 },
    xAxis: props.horizontal
      ? { type: 'value', splitLine: { lineStyle: { color: colors.grid } }, axisLabel: { color: colors.muted } }
      : { type: 'category', data: props.xData, axisLabel: { color: colors.muted }, axisLine: { lineStyle: { color: colors.axis } } },
    yAxis: props.horizontal
      ? { type: 'category', data: props.xData, axisLabel: { color: colors.muted } }
      : { type: 'value', splitLine: { lineStyle: { color: colors.grid } }, axisLabel: { color: colors.muted } },
    series: [{ type: 'bar', data: props.data, itemStyle: { color: props.color || colors.primary, borderRadius: 3 }, barWidth: '55%' }],
  }
})
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
