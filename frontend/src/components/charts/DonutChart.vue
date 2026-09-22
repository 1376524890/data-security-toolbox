<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'
import { chartColors, themeMode } from '../../utils/theme'

const props = defineProps<{
  data: Array<{ name: string; value: number; itemStyle?: { color?: string } }>
  colors?: string[]
  height?: number | string
}>()

const option = computed<echarts.EChartsOption>(() => {
  themeMode.value
  const colors = chartColors()
  return {
    tooltip: { trigger: 'item' },
    legend: { textStyle: { color: colors.muted }, bottom: 0 },
    color: props.colors,
    series: [{
      type: 'pie',
      radius: ['46%', '72%'],
      center: ['50%', '44%'],
      // The separator is the card behind the ring, not a fixed dark grey.
      itemStyle: { borderColor: 'transparent', borderWidth: 2 },
      label: { color: colors.muted },
      data: props.data,
    }],
  }
})
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
