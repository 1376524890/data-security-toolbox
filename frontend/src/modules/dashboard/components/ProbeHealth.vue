<script setup lang="ts">
/**
 * 探针健康状态: the server's own status histogram plus each probe's heartbeat.
 *
 * The online rate is drawn from the counts the overview reports (the 90 s
 * heartbeat rule lives on the server), never re-derived from ``last_seen`` here.
 */
import { computed } from 'vue'
import type { Probe } from '../../../api/probes'

const props = defineProps<{
  counts: { total: number; online: number; degraded: number; offline: number }
  probes: Probe[]
}>()

const rate = computed(() =>
  props.counts.total ? Math.round((props.counts.online / props.counts.total) * 100) : 0)

/** Worst first: an operator reads the exceptions, not the happy rows. */
const rows = computed(() => [...props.probes].sort((a, b) => rank(a) - rank(b)).slice(0, 6))

function rank(probe: Probe): number {
  return probe.status === 'online' ? 2 : probe.status === 'degraded' ? 1 : 0
}
function heartbeat(value?: string | null): string {
  if (!value) return '从未上报'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000))
  if (seconds < 60) return `${seconds} 秒前`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}
const statusText: Record<string, string> = { online: '在线', degraded: '降级', offline: '离线' }
</script>

<template>
  <section class="ds-panel">
    <div class="ds-panel-head"><span class="ds-panel-title">探针健康状态</span></div>
    <div class="ds-panel-body">
      <div class="ds-probe-top">
        <div class="ds-ring" :style="{ '--rate': `${rate * 3.6}deg` }">
          <div class="ds-ring-inner">
            <span class="ds-ring-value">{{ rate }}%</span>
            <span class="ds-ring-label">在线率</span>
          </div>
        </div>
        <ul class="ds-probe-counts">
          <li><i style="background:#2ee6a8" />在线 <b>{{ counts.online }}</b></li>
          <li><i style="background:#f5b638" />降级 <b>{{ counts.degraded }}</b></li>
          <li><i style="background:#7f9bc0" />离线 <b>{{ counts.offline }}</b></li>
          <li class="total">总计 <b>{{ counts.total }}</b></li>
        </ul>
      </div>
      <ul v-if="rows.length" class="ds-probe-list">
        <li v-for="probe in rows" :key="probe.id">
          <span class="ds-probe-name" :title="probe.ip_address">{{ probe.name }}</span>
          <span class="ds-probe-state" :class="probe.status">{{ statusText[probe.status] || probe.status }}</span>
          <span class="ds-probe-time">{{ heartbeat(probe.last_seen) }}</span>
        </li>
      </ul>
      <div v-else class="ds-probe-none">暂无已注册探针</div>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18); background: rgba(11, 30, 54, 0.82);
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
.ds-panel-body { flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 6px; }
.ds-probe-top { display: flex; align-items: center; gap: 14px; }
.ds-ring {
  width: 84px; height: 84px; border-radius: 50%; flex-shrink: 0;
  background: conic-gradient(#2ee6a8 var(--rate), rgba(53, 160, 255, 0.16) 0);
  display: grid; place-items: center;
}
.ds-ring-inner {
  width: 68px; height: 68px; border-radius: 50%; background: #0b1e36;
  display: grid; place-items: center; line-height: 1.1;
}
.ds-ring-value { font-size: 18px; font-weight: 700; color: #eaf4ff; }
.ds-ring-label { font-size: 10px; color: #6f90b3; }
.ds-probe-counts { list-style: none; margin: 0; padding: 0; font-size: 11px; color: #a9c6e2; }
.ds-probe-counts li { display: flex; align-items: center; gap: 6px; padding: 2px 0; }
.ds-probe-counts i { width: 7px; height: 7px; border-radius: 50%; }
.ds-probe-counts b { color: #eaf4ff; font-variant-numeric: tabular-nums; }
.ds-probe-counts .total { color: #6f90b3; }
.ds-probe-list { list-style: none; margin: 0; padding: 0; overflow: auto; }
.ds-probe-list li {
  display: grid; grid-template-columns: 1fr auto auto; gap: 8px; align-items: center;
  font-size: 10px; color: #a9c6e2; padding: 3px 0;
  border-top: 1px solid rgba(53, 160, 255, 0.08);
}
.ds-probe-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ds-probe-state.online { color: #2ee6a8; }
.ds-probe-state.degraded { color: #f5b638; }
.ds-probe-state.offline { color: #7f9bc0; }
.ds-probe-time { color: #6f90b3; }
.ds-probe-none { color: #5b7799; font-size: 11px; }
</style>
