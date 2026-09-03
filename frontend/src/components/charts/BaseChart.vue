<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'

const props = defineProps<{ option: echarts.EChartsOption; height?: number | string }>()
const el = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null

const resize = () => chart?.resize()

function render(): void {
  if (!el.value) return
  if (!chart) chart = echarts.init(el.value)
  chart.setOption(props.option, true)
}

watch(() => props.option, render, { deep: true })
onMounted(() => {
  render()
  window.addEventListener('resize', resize)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', resize)
  chart?.dispose()
  chart = null
})
</script>

<template>
  <div ref="el" class="base-chart" :style="{ height: typeof height === 'number' ? `${height}px` : height || '280px' }" />
</template>

<style scoped>
.base-chart { width: 100%; }
</style>
