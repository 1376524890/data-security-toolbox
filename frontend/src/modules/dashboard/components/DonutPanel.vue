<script setup lang="ts">
/**
 * A ring plus its legend table. The legend is real markup rather than an ECharts
 * legend so the counts and shares stay aligned in columns, which is what makes a
 * donut readable from across a room.
 */
import { computed } from 'vue'
import BaseChart from '../../../components/charts/BaseChart.vue'
import { donutOption, donutPalette } from '../chartTheme'

const props = defineProps<{
  title: string
  slices: Array<{ name: string; value: number; color?: string }>
  total: number
  unit?: string
  emptyText?: string
}>()

const option = computed(() => donutOption(props.slices))
const rows = computed(() => {
  const total = props.slices.reduce((sum, item) => sum + Number(item.value || 0), 0)
  return props.slices.map((item, index) => ({
    name: item.name,
    value: item.value,
    color: item.color || donutPalette[index % donutPalette.length],
    percent: total ? Math.round((Number(item.value) / total) * 1000) / 10 : 0,
  }))
})
const hasData = computed(() => rows.value.length > 0)
</script>

<template>
  <section class="ds-panel">
    <div class="ds-panel-head">
      <span class="ds-panel-title">{{ title }}</span>
      <slot name="actions" />
    </div>
    <div class="ds-panel-body">
      <template v-if="hasData">
        <div class="ds-donut">
          <BaseChart :option="option" height="100%" />
          <div class="ds-donut-center">
            <div class="ds-donut-value">{{ total }}</div>
            <div class="ds-donut-label">总计{{ unit ? `（${unit}）` : '' }}</div>
          </div>
        </div>
        <ul class="ds-legend">
          <li v-for="row in rows" :key="row.name">
            <i class="ds-legend-dot" :style="{ background: row.color }" />
            <span class="ds-legend-name">{{ row.name }}</span>
            <span class="ds-legend-value">{{ row.value }}</span>
            <span class="ds-legend-percent">{{ row.percent }}%</span>
          </li>
        </ul>
      </template>
      <div v-else class="ds-empty">{{ emptyText || '暂无数据' }}</div>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18);
  background: rgba(11, 30, 54, 0.82);
}
.ds-panel-head { display: flex; align-items: center; justify-content: space-between; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-panel-body { flex: 1; min-height: 0; display: flex; align-items: center; gap: 6px; }
.ds-donut { position: relative; width: 52%; height: 100%; }
.ds-donut :deep(.base-chart) { height: 100% !important; }
.ds-donut-center {
  position: absolute; left: 38%; top: 52%; transform: translate(-50%, -50%);
  text-align: center; pointer-events: none;
}
.ds-donut-value { font-size: 20px; font-weight: 700; color: #eaf4ff; font-variant-numeric: tabular-nums; }
.ds-donut-label { font-size: 10px; color: #6f90b3; }
.ds-legend { flex: 1; list-style: none; margin: 0; padding: 0; min-width: 0; }
.ds-legend li {
  display: grid; grid-template-columns: 8px 1fr auto auto; align-items: center; gap: 6px;
  font-size: 11px; color: #a9c6e2; padding: 3px 0;
}
.ds-legend-dot { width: 8px; height: 8px; border-radius: 2px; }
.ds-legend-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ds-legend-value { font-weight: 600; color: #eaf4ff; font-variant-numeric: tabular-nums; }
.ds-legend-percent { color: #6f90b3; width: 42px; text-align: right; font-variant-numeric: tabular-nums; }
.ds-empty { width: 100%; display: grid; place-items: center; font-size: 12px; color: #5b7799; }
</style>
