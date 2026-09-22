<script setup lang="ts">
/**
 * 检测引擎运行状态.
 *
 * The rows come from the integration catalogue the console already trusts, so a
 * component reported as 运行中 here is the same component the console lists as
 * ready; the rule and finding columns are the adapter's own counts.
 */
import type { EngineRow } from '../composables/useDashboardScreen'

defineProps<{
  rows: EngineRow[]
  summary: { total: number; running: number; error: number; stopped: number }
}>()

const stateClass: Record<string, string> = { running: 'ok', error: 'bad', stopped: 'off' }
</script>

<template>
  <section class="ds-panel">
    <div class="ds-panel-head">
      <span class="ds-panel-title">检测引擎运行状态</span>
      <span class="ds-panel-meta">
        共 {{ summary.total }} · 运行中 {{ summary.running }}
        <b v-if="summary.error" class="bad">异常 {{ summary.error }}</b>
        <b v-if="summary.stopped" class="off">已停止 {{ summary.stopped }}</b>
      </span>
    </div>
    <div class="ds-panel-body">
      <table v-if="rows.length" class="ds-table">
        <thead>
          <tr><th>组件</th><th>类型</th><th class="num">规则</th><th class="num">发现</th><th>状态</th></tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.name" :title="row.version">
            <td class="name">{{ row.label }}</td>
            <td class="dim">{{ row.category }}</td>
            <td class="num">{{ row.ruleCount ?? '—' }}</td>
            <td class="num">{{ row.findings }}</td>
            <td><span class="ds-state" :class="stateClass[row.state]">{{ row.stateLabel }}</span></td>
          </tr>
        </tbody>
      </table>
      <div v-else class="ds-empty">暂无引擎数据</div>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18); background: rgba(11, 30, 54, 0.82);
}
.ds-panel-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-panel-meta { font-size: 10px; color: #6f90b3; }
.ds-panel-meta b { font-weight: 600; margin-left: 4px; }
.ds-panel-meta .bad { color: #ff4d5e; }
.ds-panel-meta .off { color: #8aa6c6; }
.ds-panel-body { flex: 1; min-height: 0; overflow: auto; }
.ds-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.ds-table th {
  text-align: left; font-weight: 500; color: #6f90b3; padding: 2px 4px;
  border-bottom: 1px solid rgba(53, 160, 255, 0.14); position: sticky; top: 0;
  background: rgba(11, 30, 54, 0.96);
}
.ds-table td { padding: 2px 4px; color: #a9c6e2; border-bottom: 1px solid rgba(53, 160, 255, 0.07); }
.ds-table .name { color: #eaf4ff; }
.ds-table .dim { color: #7f9bc0; }
.ds-table .num { text-align: right; font-variant-numeric: tabular-nums; }
.ds-state { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; }
.ds-state::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.ds-state.ok { color: #2ee6a8; }
.ds-state.bad { color: #ff4d5e; animation: ds-blink 1.8s ease-in-out infinite; }
.ds-state.off { color: #7f9bc0; }
@keyframes ds-blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.45; } }
@media (prefers-reduced-motion: reduce) { .ds-state.bad { animation: none; } }
.ds-empty { display: grid; place-items: center; height: 100%; color: #5b7799; font-size: 12px; }
</style>
