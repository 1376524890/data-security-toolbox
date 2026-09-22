<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'
import { chartColors, themeMode } from '../../utils/theme'

const props = defineProps<{
  xData: string[]
  series: Array<{ name: string; data: number[]; color?: string; area?: boolean }>
  height?: number | string
}>()

const option = computed<echarts.EChartsOption>(() => {
  themeMode.value
  const colors = chartColors()
  return {
  tooltip: { trigger: 'axis' },
  legend: { textStyle: { color: colors.muted }, top: 0 },
  grid: { left: 44, right: 20, top: 32, bottom: 30 },
  xAxis: { type: 'category', data: props.xData, axisLine: { lineStyle: { color: colors.axis } }, axisLabel: { color: colors.muted } },
  yAxis: { type: 'value', splitLine: { lineStyle: { color: colors.grid } }, axisLabel: { color: colors.muted } },
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
  }
})
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
