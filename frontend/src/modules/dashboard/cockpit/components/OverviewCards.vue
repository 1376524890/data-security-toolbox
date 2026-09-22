<script setup lang="ts">
/**
 * The KPI band: eight cards, each a live count with its week window.
 *
 * The trend line is honest about a missing denominator - "上周无数据" instead of
 * a "+100%" that would read as growth the platform never measured.
 */
import { computed } from 'vue'
import type { CockpitMetric } from '../composables/useDashboardCockpit'

const props = defineProps<{ items: CockpitMetric[] }>()
defineEmits<{ open: [item: CockpitMetric] }>()

function formatted(value: number): string {
  return Number(value || 0).toLocaleString('zh-CN')
}

const rows = computed(() => props.items)
function trendText(item: CockpitMetric): string {
  if (item.delta_pct === null) return '上周无数据'
  return `${item.delta_pct > 0 ? '+' : ''}${item.delta_pct}%`
}
function trendTone(item: CockpitMetric): string {
  if (item.delta_pct === null) return 'flat'
  if (item.delta_pct > 0) return item.riseIsBad === false ? 'up' : 'bad'
  return item.riseIsBad === false ? 'bad' : 'up'
}
</script>

<template>
  <div class="ov-grid">
    <button v-for="item in rows" :key="item.key" type="button" class="ov-card"
            :title="item.hint" @click="$emit('open', item)">
      <span class="ov-icon" :style="{ background: `${item.color}14`, color: item.color }">
        <el-icon :size="20"><component :is="item.icon" /></el-icon>
      </span>
      <span class="ov-main">
        <span class="ov-label">{{ item.label }}</span>
        <span class="ov-value">
          {{ formatted(item.value) }}<em v-if="item.unit">{{ item.unit }}</em>
        </span>
        <span class="ov-foot">
          <span class="ov-trend" :class="trendTone(item)">
            <el-icon v-if="item.delta_pct !== null" :size="12">
              <component :is="item.delta_pct > 0 ? 'CaretTop' : 'CaretBottom'" />
            </el-icon>
            {{ trendText(item) }}
          </span>
          <span class="ov-hint">较上周</span>
        </span>
      </span>
    </button>
  </div>
</template>

<style scoped>
.ov-grid {
  display: grid; gap: 12px;
  grid-template-columns: repeat(8, minmax(0, 1fr));
}
/* Eight across needs ~165px per card; below that the band folds to two rows
   rather than shrinking the numbers into the icon. */
@media (max-width: 1439px) { .ov-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); } }
@media (max-width: 1000px) { .ov-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.ov-card {
  display: flex; align-items: center; gap: 12px; text-align: left; cursor: pointer;
  padding: 14px 14px; background: var(--soc-panel); border: 1px solid var(--soc-border);
  border-radius: var(--soc-radius-lg, 10px); box-shadow: var(--soc-shadow);
  transition: border-color 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
  font: inherit; color: inherit; min-width: 0;
}
.ov-card:hover {
  border-color: var(--soc-primary); transform: translateY(-1px);
  box-shadow: var(--soc-shadow-lg);
}
.ov-icon {
  width: 40px; height: 40px; border-radius: 10px; flex-shrink: 0;
  display: inline-flex; align-items: center; justify-content: center;
}
.ov-main { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ov-label { font-size: 12px; color: var(--soc-text-muted); white-space: nowrap; }
.ov-value {
  font-size: 24px; font-weight: 700; line-height: 1.15; color: var(--soc-text-strong);
  font-variant-numeric: tabular-nums; white-space: nowrap;
}
.ov-value em { font-size: 12px; font-style: normal; font-weight: 500; margin-left: 2px; color: var(--soc-text-muted); }
/* The trend sits above its label, as on the reference: eight cards in one row
   leave ~72px of text width, and "上周无数据较上周" on one line would wrap
   mid-word. */
.ov-foot { display: flex; flex-direction: column; align-items: flex-start; font-size: 11px; }
.ov-trend { display: inline-flex; align-items: center; gap: 1px; font-weight: 600; white-space: nowrap; }
.ov-hint { white-space: nowrap; }
.ov-trend.up { color: var(--soc-success); }
.ov-trend.bad { color: var(--soc-danger); }
.ov-trend.flat { color: var(--soc-text-dim); font-weight: 400; }
.ov-hint { color: var(--soc-text-dim); }
</style>
