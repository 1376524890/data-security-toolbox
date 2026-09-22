<script setup lang="ts">
/**
 * 数据流动审计: sessions per day by direction, plus the two headline totals.
 *
 * All three classes the classifier can return are drawn - dropping
 * 目的未识别 would make an unproven destination look like an internal one.
 * A delta of ``null`` (no sessions in the week before) prints "上周无数据"
 * instead of a percentage against zero.
 */
import { computed } from 'vue'
import BaseChart from '../../../../components/charts/BaseChart.vue'
import CockpitCard from './CockpitCard.vue'
import { barOption, directionColors, directionLabels } from '../chartTheme'
import { shortDay, type CockpitRange, type CockpitTrendPoint } from '../composables/useDashboardCockpit'
import type { FlowDirection, FlowDirectionTotals, WeekWindow } from '../../../../types/dashboard'

const props = defineProps<{
  trend: CockpitTrendPoint[]
  totals: Record<FlowDirection, FlowDirectionTotals> | null
  weekly: Record<FlowDirection, WeekWindow> | null
  range: CockpitRange
}>()
defineEmits<{ open: []; range: [value: CockpitRange] }>()

const RANGES: Array<{ key: CockpitRange; label: string }> = [
  { key: '7d', label: '近 7 天' },
  { key: '24h', label: '近 24 小时' },
]

const DIRECTIONS: FlowDirection[] = ['internal', 'external', 'unknown']

const x = computed(() => props.trend.map((item) => shortDay(item.time)))
const series = computed(() => DIRECTIONS.map((direction) => ({
  name: directionLabels[direction],
  data: props.trend.map((item) => Number(item[direction] || 0)),
  color: directionColors[direction],
})))
const option = computed(() => barOption(x.value, series.value))
const hasData = computed(() => props.trend.length > 0)

/** The two headline boxes: real sessions out and real sessions in. */
const head = computed(() => (['external', 'internal'] as const).map((direction) => ({
  key: direction,
  label: `${direction === 'external' ? '外部流出' : '内部流动'}事件`,
  color: directionColors[direction],
  value: props.totals?.[direction]?.sessions ?? 0,
  delta: props.weekly?.[direction]?.delta_pct ?? null,
})))

function deltaText(value: number | null): string {
  if (value === null) return '上周无数据'
  return `${value > 0 ? '+' : ''}${value}%`
}
</script>

<template>
  <CockpitCard title="数据流动审计" action="更多" @action="$emit('open')">
    <template #actions>
      <div class="df-tabs">
        <button v-for="item in RANGES" :key="item.key" type="button" class="df-tab"
                :class="{ active: item.key === range }" @click="$emit('range', item.key)">
          {{ item.label }}
        </button>
      </div>
    </template>
    <div class="df">
      <BaseChart v-if="hasData" :option="option" height="168px" />
      <div v-else class="df-empty">所选时间范围内没有会话记录</div>
      <div class="df-head">
        <div v-for="item in head" :key="item.key" class="df-box">
          <div class="df-box-label">{{ item.label }}</div>
          <div class="df-box-value">
            <b :style="{ color: item.color }">{{ item.value.toLocaleString('zh-CN') }}</b>
            <span class="df-delta" :class="item.delta !== null && item.delta > 0 ? 'bad' : 'up'">
              {{ deltaText(item.delta) }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </CockpitCard>
</template>

<style scoped>
.df { display: flex; flex-direction: column; gap: 10px; }
.df-tabs { display: inline-flex; gap: 4px; }
.df-tab {
  border: 1px solid var(--soc-border); background: var(--soc-panel); cursor: pointer;
  font-size: 11px; color: var(--soc-text-muted); padding: 2px 8px; border-radius: 6px;
  font-family: inherit;
}
.df-tab:hover { color: var(--soc-primary); border-color: var(--soc-primary); }
.df-tab.active { color: #fff; border-color: var(--soc-primary); background: var(--soc-primary); }
.df-empty {
  height: 168px; display: flex; align-items: center; justify-content: center;
  color: var(--soc-text-dim); font-size: 12px;
}
.df-head { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.df-box {
  border: 1px solid var(--soc-border); border-radius: 8px; padding: 8px 12px;
  background: var(--soc-panel-2, transparent);
}
.df-box-label { font-size: 11px; color: var(--soc-text-muted); }
.df-box-value { display: flex; align-items: baseline; gap: 8px; margin-top: 2px; }
.df-box-value b { font-size: 20px; font-weight: 700; font-variant-numeric: tabular-nums; }
.df-delta { font-size: 11px; color: var(--soc-text-dim); }
.df-delta.bad { color: var(--soc-danger); }
.df-delta.up { color: var(--soc-success); }
</style>
