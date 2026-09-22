<script setup lang="ts">
/**
 * A trend card: title bar (with room for a series switch), the line body and an
 * optional footnote. Both the 数据流动态势 and the 检测趋势 cards are this
 * component, so the two series on the wall always share one axis style.
 */
import { computed } from 'vue'
import BaseChart from '../../../components/charts/BaseChart.vue'
import { lineOption } from '../chartTheme'

const props = defineProps<{
  title: string
  x: string[]
  series: Array<{ name: string; data: number[]; color: string; area?: boolean }>
  footnote?: string
  empty?: boolean
  emptyText?: string
  legend?: boolean
}>()

const option = computed(() => lineOption(props.x, props.series, { legend: props.legend }))
const hasData = computed(() =>
  !props.empty && props.x.length > 0
  && props.series.some((item) => item.data.some((value) => Number(value) > 0)))
</script>

<template>
  <section class="ds-panel">
    <div class="ds-panel-head">
      <span class="ds-panel-title">{{ title }}</span>
      <div class="ds-panel-actions"><slot name="actions" /></div>
    </div>
    <div class="ds-panel-body">
      <BaseChart v-if="hasData" :option="option" height="100%" />
      <div v-else class="ds-empty">{{ emptyText || '暂无数据' }}</div>
    </div>
    <div v-if="footnote" class="ds-panel-foot">{{ footnote }}</div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18);
  background: rgba(11, 30, 54, 0.82);
}
.ds-panel-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-panel-actions { display: flex; gap: 4px; }
.ds-panel-body { flex: 1; min-height: 0; position: relative; }
.ds-panel-body :deep(.base-chart) { height: 100% !important; }
.ds-panel-foot { font-size: 10px; color: #5b7799; padding-top: 2px; }
.ds-empty {
  height: 100%; display: grid; place-items: center; font-size: 12px; color: #5b7799;
}
</style>
