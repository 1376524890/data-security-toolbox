<script setup lang="ts">
/**
 * 本周重点关注: the rows a 负责人 has to act on.
 *
 * Each row carries its own trend, and clicking one opens the page that owns the
 * data behind it (the mapping lives in the composable).
 */
import type { FocusItem } from '../composables/useDashboardCockpit'
import type { FocusRow } from '../../../../types/dashboard'

defineProps<{ items: FocusItem[] }>()
defineEmits<{ open: [item: FocusItem] }>()

function deltaText(item: FocusRow): string {
  if (item.delta_pct === null) return ''
  return `较上周 ${item.delta_pct > 0 ? '+' : ''}${item.delta_pct}%`
}
function value(item: FocusRow): string {
  return item.value === null ? '—' : item.value.toLocaleString('zh-CN')
}
</script>

<template>
  <ul class="wf">
    <li v-for="item in items" :key="item.key" tabindex="0" role="button"
        @click="$emit('open', item)" @keydown.enter="$emit('open', item)">
      <span class="wf-icon" :style="{ background: `${item.color}14`, color: item.color }">
        <el-icon :size="15"><component :is="item.icon" /></el-icon>
      </span>
      <span class="wf-label">{{ item.label }}</span>
      <span class="wf-value" :style="{ color: item.color }">
        {{ value(item) }}<em>{{ item.unit }}</em>
      </span>
      <span class="wf-tail">
        <span v-if="deltaText(item)" class="wf-delta"
              :class="item.delta_pct !== null && item.delta_pct > 0 ? 'bad' : 'up'">
          {{ deltaText(item) }}
        </span>
        <span v-else class="wf-hint">{{ item.hint }}</span>
      </span>
    </li>
  </ul>
</template>

<style scoped>
.wf { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
.wf li {
  display: grid; grid-template-columns: 26px 1fr auto 96px;
  align-items: center; gap: 10px; padding: 9px 6px; cursor: pointer;
  border-radius: 6px; border-bottom: 1px solid var(--soc-border);
}
.wf li:last-child { border-bottom: 0; }
.wf li:hover { background: var(--soc-panel-hover); }
.wf-icon {
  width: 26px; height: 26px; border-radius: 8px;
  display: inline-flex; align-items: center; justify-content: center;
}
.wf-label {
  font-size: 13px; color: var(--soc-text); min-width: 0;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.wf-value { font-size: 16px; font-weight: 700; font-variant-numeric: tabular-nums; }
.wf-value em { font-size: 11px; font-style: normal; font-weight: 500; margin-left: 2px; color: var(--soc-text-muted); }
.wf-tail { font-size: 11px; color: var(--soc-text-dim); text-align: right; }
.wf-hint { color: var(--soc-text-dim); }
.wf-delta.bad { color: var(--soc-danger); }
.wf-delta.up { color: var(--soc-success); }
</style>
