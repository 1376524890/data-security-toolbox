<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'

const props = defineProps<{
  data: Array<{ name: string; value: number }>
  colors?: string[]
  height?: number | string
}>()

const option = computed<echarts.EChartsOption>(() => ({
  tooltip: { trigger: 'item' },
  legend: { textStyle: { color: '#9ca3af' }, bottom: 0 },
  color: props.colors,
  series: [{
    type: 'pie',
    radius: ['46%', '72%'],
    center: ['50%', '44%'],
    itemStyle: { borderColor: '#111827', borderWidth: 2 },
    label: { color: '#9ca3af' },
    data: props.data,
  }],
}))
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
