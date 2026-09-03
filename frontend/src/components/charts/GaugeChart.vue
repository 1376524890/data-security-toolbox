<script setup lang="ts">
import { computed } from 'vue'
import type * as echarts from 'echarts'
import BaseChart from './BaseChart.vue'

const props = defineProps<{ value: number; max?: number; color?: string; height?: number | string }>()
const option = computed<echarts.EChartsOption>(() => ({
  series: [{
    type: 'gauge',
    startAngle: 210,
    endAngle: -30,
    min: 0,
    max: props.max || 100,
    progress: { show: true, width: 12, itemStyle: { color: props.color || '#38bdf8' } },
    axisLine: { lineStyle: { width: 12, color: [[1, '#1f2937']] } },
    pointer: { show: false },
    axisTick: { show: false },
    splitLine: { show: false },
    axisLabel: { show: false },
    detail: { valueAnimation: true, formatter: '{value}', color: '#e5e7eb', fontSize: 28, offsetCenter: [0, '10%'] },
    data: [{ value: props.value }],
  }],
}))
</script>

<template>
  <BaseChart :option="option" :height="height" />
</template>
