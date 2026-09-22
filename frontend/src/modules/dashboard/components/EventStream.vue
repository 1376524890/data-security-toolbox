<script setup lang="ts">
/**
 * 实时安全事件: the newest alerts, time-first.
 *
 * The list scrolls itself only when it actually overflows (a short list must not
 * drift), pauses while the pointer is over it so an operator can read a row, and
 * stops entirely when the platform asks for reduced motion.
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import SeverityTag from '../../../components/security/SeverityTag.vue'
import type { Alert } from '../../../types/alert'

const props = defineProps<{ events: Alert[] }>()

const viewport = ref<HTMLElement | null>(null)
let frame = 0
// A ref, not a plain `let`: vue-tsc narrows a let binding to its initialiser's
// literal type, and then rejects the template's `paused = true`.
const paused = ref(false)

function reduceMotion(): boolean {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function step(): void {
  const el = viewport.value
  if (!el) { frame = 0; return }
  const overflow = el.scrollHeight - el.clientHeight
  if (overflow <= 4 || paused.value || reduceMotion()) { frame = 0; return }
  if (el.scrollTop >= overflow - 0.5) el.scrollTop = 0
  else el.scrollTop += 0.35
  frame = requestAnimationFrame(step)
}

function start(): void {
  if (frame || !viewport.value) return
  frame = requestAnimationFrame(step)
}

watch(() => props.events, () => { start() }, { deep: false })
onMounted(start)
onBeforeUnmount(() => { if (frame) cancelAnimationFrame(frame) })

function time(value?: string | null): string {
  if (!value) return '--:--:--'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value).slice(11, 19) || '--:--:--'
  return date.toLocaleTimeString('zh-CN', { hour12: false })
}

const rows = computed(() => props.events)
</script>

<template>
  <section class="ds-panel">
    <div class="ds-panel-head">
      <span class="ds-panel-title">实时安全事件</span>
      <span class="ds-panel-meta">按最近上报排序</span>
    </div>
    <div class="ds-panel-body">
      <div v-if="rows.length" ref="viewport" class="ds-events"
           @mouseenter="paused = true" @mouseleave="paused = false">
        <div v-for="item in rows" :key="item.id" class="ds-event">
          <span class="ds-event-time">{{ time(item.last_seen || item.created_at) }}</span>
          <span class="ds-event-title" :title="item.summary || item.title">{{ item.title }}</span>
          <SeverityTag :value="item.severity" />
          <span class="ds-event-source" :title="item.source">{{ item.source }}</span>
        </div>
      </div>
      <div v-else class="ds-empty">暂无告警</div>
    </div>
  </section>
</template>

<style scoped>
.ds-panel {
  display: flex; flex-direction: column; height: 100%; min-height: 0; padding: 8px 10px 6px;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18); background: rgba(11, 30, 54, 0.82);
}
.ds-panel-head { display: flex; align-items: baseline; justify-content: space-between; }
.ds-panel-title {
  font-size: 13px; font-weight: 600; color: #d7e6f7; letter-spacing: 0.06em;
  padding-left: 10px; position: relative;
}
.ds-panel-title::before {
  content: ''; position: absolute; left: 0; top: 50%; width: 3px; height: 12px;
  transform: translateY(-50%); border-radius: 2px; background: linear-gradient(180deg, #35a0ff, #22d3ee);
}
.ds-panel-meta { font-size: 10px; color: #6f90b3; }
.ds-panel-body { flex: 1; min-height: 0; }
.ds-events { height: 100%; overflow: hidden; }
.ds-event {
  display: grid; grid-template-columns: 62px 1fr auto 84px; gap: 8px; align-items: center;
  padding: 3px 2px; font-size: 11px; color: #a9c6e2;
  border-bottom: 1px solid rgba(53, 160, 255, 0.07);
}
.ds-event-time { color: #6f90b3; font-variant-numeric: tabular-nums; }
.ds-event-title { color: #dbeaf9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ds-event-source { color: #7f9bc0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: right; }
.ds-empty { display: grid; place-items: center; height: 100%; color: #5b7799; font-size: 12px; }
</style>
