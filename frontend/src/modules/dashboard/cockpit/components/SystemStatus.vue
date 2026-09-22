<script setup lang="ts">
/**
 * 探针与引擎状态: four rows, each an up/total pair with its real percentage.
 *
 * A row with no registered item shows "—" rather than 0%: nothing to watch is
 * not the same as everything broken.
 */
import { computed } from 'vue'
import type { StatusRow } from '../../../../types/dashboard'

const props = defineProps<{ items: StatusRow[] }>()
const rows = computed(() => props.items)

const ICONS: Record<string, string> = {
  probes: 'Monitor',
  integrations: 'Connection',
  engines: 'Cpu',
  collection: 'FolderOpened',
}
function tone(rate: number | null): string {
  if (rate === null) return 'var(--soc-text-dim)'
  if (rate >= 80) return 'var(--soc-success)'
  if (rate >= 50) return 'var(--soc-warning)'
  return 'var(--soc-danger)'
}
</script>

<template>
  <ul class="ss">
    <li v-for="row in rows" :key="row.key">
      <span class="ss-icon"><el-icon :size="15"><component :is="ICONS[row.key] || 'DataLine'" /></el-icon></span>
      <span class="ss-label">{{ row.label }}</span>
      <span class="ss-count">
        <b :style="{ color: tone(row.rate) }">{{ row.up }}</b><i>/{{ row.total }}</i>
      </span>
      <span class="ss-track">
        <i :style="{ width: `${Math.min(100, row.rate ?? 0)}%`, background: tone(row.rate) }" />
      </span>
      <span class="ss-rate" :style="{ color: tone(row.rate) }">
        {{ row.rate === null ? '—' : `${row.rate}%` }}
      </span>
    </li>
  </ul>
</template>

<style scoped>
.ss { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
.ss li {
  display: grid; grid-template-columns: 26px minmax(0, 1fr) auto 72px 44px;
  align-items: center; gap: 10px; padding: 8px 6px; border-radius: 6px;
}
.ss li:hover { background: var(--soc-panel-hover); }
.ss-icon {
  width: 26px; height: 26px; border-radius: 8px; display: inline-flex;
  align-items: center; justify-content: center;
  background: var(--soc-primary-dim); color: var(--soc-primary);
}
/* A label that cannot fit is elided, never wrapped one character per line. */
.ss-label {
  font-size: 13px; color: var(--soc-text); min-width: 0;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.ss-count { font-size: 13px; font-variant-numeric: tabular-nums; }
.ss-count b { font-weight: 700; }
.ss-count i { font-style: normal; color: var(--soc-text-dim); }
.ss-track { height: 6px; border-radius: 3px; background: var(--soc-panel-hover); overflow: hidden; }
.ss-track i { display: block; height: 100%; border-radius: 3px; transition: width 0.3s ease; }
.ss-rate { font-size: 12px; font-weight: 700; text-align: right; font-variant-numeric: tabular-nums; }
</style>
