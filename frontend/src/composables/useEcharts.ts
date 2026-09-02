import { onBeforeUnmount, onMounted, type Ref } from 'vue'
import * as echarts from 'echarts'

export function useEcharts(el: Ref<HTMLElement | null>) {
  let chart: echarts.ECharts | null = null
  const resize = () => chart?.resize()

  function setOption(option: echarts.EChartsOption): void {
    if (!el.value) return
    if (!chart) chart = echarts.init(el.value)
    chart.setOption(option, true)
  }

  onMounted(() => {
    window.addEventListener('resize', resize)
  })
  onBeforeUnmount(() => {
    window.removeEventListener('resize', resize)
    chart?.dispose()
    chart = null
  })

  return { setOption }
}
