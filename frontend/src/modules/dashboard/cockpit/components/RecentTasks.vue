<script setup lang="ts">
/**
 * 最近任务: the newest task rows, straight from ``GET /dashboard/tasks``.
 *
 * The status pill is the console's shared StatusBadge, so a state reads the same
 * here as it does in 任务中心. The row is clickable and opens the task centre.
 */
import { computed } from 'vue'
import CockpitCard from './CockpitCard.vue'
import StatusBadge from '../../../../components/security/StatusBadge.vue'
import type { TaskRow } from '../composables/useDashboardCockpit'

const props = defineProps<{ rows: TaskRow[] }>()
defineEmits<{ open: [row: TaskRow] }>()

const rows = computed(() => props.rows)
</script>

<template>
  <CockpitCard title="最近任务" action="更多" @action="$emit('open', { id: 0 } as TaskRow)">
    <table class="rt">
      <thead>
        <tr>
          <th class="rt-name">任务名称</th>
          <th class="rt-kind">任务类型</th>
          <th class="rt-status">状态</th>
          <th class="rt-time">开始时间</th>
          <th class="rt-op">操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="row.id" @click="$emit('open', row)">
          <td class="rt-name" :title="row.name">{{ row.name }}</td>
          <td class="rt-kind">{{ row.kind_label }}</td>
          <td class="rt-status"><StatusBadge :value="row.status" /></td>
          <td class="rt-time">{{ row.started_text }}</td>
          <td class="rt-op"><button type="button" class="rt-link">查看</button></td>
        </tr>
        <tr v-if="!rows.length">
          <td colspan="5" class="rt-empty">还没有任务</td>
        </tr>
      </tbody>
    </table>
  </CockpitCard>
</template>

<style scoped>
.rt { width: 100%; border-collapse: collapse; font-size: 12px; }
.rt th {
  text-align: left; font-weight: 500; color: var(--soc-text-muted); font-size: 11px;
  padding: 6px 8px; border-bottom: 1px solid var(--soc-border); white-space: nowrap;
}
.rt td {
  padding: 8px; border-bottom: 1px solid var(--soc-border); color: var(--soc-text);
  vertical-align: middle;
}
.rt tbody tr { cursor: pointer; }
.rt tbody tr:hover { background: var(--soc-panel-hover); }
.rt tbody tr:last-child td { border-bottom: 0; }
.rt-name { max-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; width: 40%; }
.rt-kind, .rt-status, .rt-op { white-space: nowrap; }
.rt-time { color: var(--soc-text-muted); font-variant-numeric: tabular-nums; white-space: nowrap; }
.rt-link {
  border: 0; background: none; padding: 0; cursor: pointer; font: inherit;
  color: var(--soc-primary);
}
.rt-link:hover { text-decoration: underline; }
.rt-empty { text-align: center; color: var(--soc-text-dim); padding: 24px 0; }
</style>
