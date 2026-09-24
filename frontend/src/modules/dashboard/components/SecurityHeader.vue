<script setup lang="ts">
/**
 * The screen's own header: brand, title, live platform state and the clock.
 *
 * Everything it shows is passed in, so the numbers on the header and the KPI
 * band below can be fed from the same server aggregates instead of the header
 * opening a second, slightly different view of the platform.
 */
import ScreenIcon from './ScreenIcon.vue'

const props = defineProps<{
  apiStatus: string
  integrations: { healthy: number; total: number }
  probes: { online: number; total: number }
  username: string
  now: Date
}>()
defineEmits<{ fullscreen: []; console: [] }>()

const pad = (value: number) => String(value).padStart(2, '0')
function clockText(value: Date): string {
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} `
    + `${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`
}
function weekday(value: Date): string {
  return ['星期日', '星期一', '星期二', '星期三', '星期四', '星期五', '星期六'][value.getDay()]
}
const apiOk = () => props.apiStatus === 'ok'
</script>

<template>
  <header class="ds-header">
    <div class="ds-brand">
      <div class="ds-logo">
        <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true">
          <path d="M16 2 3 7v9c0 7.5 5.6 13.9 13 15 7.4-1.1 13-7.5 13-15V7L16 2z"
                fill="url(#dsLogoGradient)" />
          <path d="M16 8.5 9 11.4v4.3c0 3.6 2.8 6.7 7 7.8 4.2-1.1 7-4.2 7-7.8v-4.3L16 8.5z"
                fill="#0a2a4d" opacity="0.9" />
          <path d="M13 15.6l2.4 2.4 4.6-4.6 1.4 1.4-6 6-3.8-3.8z" fill="#04182e" />
          <defs>
            <linearGradient id="dsLogoGradient" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stop-color="#35a0ff" />
              <stop offset="100%" stop-color="#22d3ee" />
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div class="ds-brand-text">
        <div class="ds-brand-name">数据安全监测检测工具箱</div>
        <div class="ds-brand-sub">数据安全 · 监测 · 分析 · 处置</div>
      </div>
    </div>

    <div class="ds-title-block">
      <h1 class="ds-title">数据安全态势大屏</h1>
      <div class="ds-subtitle">全域数据可视 · 风险实时感知 · 合规持续保障</div>
    </div>

    <div class="ds-status">
      <span class="ds-chip" :class="{ ok: apiOk() }">
        <i class="ds-dot" />
        API {{ apiOk() ? '正常' : (apiStatus || '未知') }}
      </span>
      <span class="ds-chip">
        <ScreenIcon name="engine" :size="14" />
        集成组件 {{ integrations.healthy }}/{{ integrations.total }}
      </span>
      <span class="ds-chip" :class="{ ok: probes.online > 0 }">
        <ScreenIcon name="probe" :size="14" />
        在线探针 {{ probes.online }}<span class="ds-dim">/{{ probes.total }}</span>
      </span>
      <span class="ds-clock">
        {{ clockText(now) }}<span class="ds-dim">{{ weekday(now) }}</span>
      </span>
      <span class="ds-user">{{ username || '—' }}</span>
      <button class="ds-icon-button" type="button" title="全屏" @click="$emit('fullscreen')">
        <ScreenIcon name="fullscreen" :size="16" />
      </button>
      <button class="ds-icon-button" type="button" title="返回控制台" @click="$emit('console')">
        <ScreenIcon name="console" :size="16" />
      </button>
    </div>
  </header>
</template>

<style scoped>
.ds-header {
  display: flex; align-items: center; gap: 22px;
  /* A fixed row, not height:100%: as a flex item of the 1080px frame a
     percentage basis lets the header claim the whole column and the middle
     row collapses to zero. */
  height: 76px; flex-shrink: 0; padding: 0 18px;
  border-bottom: 1px solid rgba(53, 160, 255, 0.22);
  background: linear-gradient(180deg, rgba(16, 44, 78, 0.9), rgba(8, 24, 44, 0.6));
}
.ds-brand { display: flex; align-items: center; gap: 10px; min-width: 300px; }
.ds-logo { filter: drop-shadow(0 0 10px rgba(53, 160, 255, 0.45)); }
.ds-brand-name { font-size: 17px; font-weight: 700; letter-spacing: 0.04em; color: #eaf4ff; }
.ds-brand-sub { font-size: 11px; color: #6f90b3; letter-spacing: 0.14em; }
.ds-title-block { flex: 1; text-align: center; }
.ds-title {
  margin: 0; font-size: 30px; font-weight: 800; letter-spacing: 0.16em;
  background: linear-gradient(180deg, #ffffff, #6dc6ff);
  -webkit-background-clip: text; background-clip: text; color: transparent;
  text-shadow: 0 0 24px rgba(53, 160, 255, 0.25);
}
.ds-subtitle { margin-top: 4px; font-size: 12px; letter-spacing: 0.22em; color: #7fa9cf; }
.ds-status { display: flex; align-items: center; gap: 12px; min-width: 520px; justify-content: flex-end; }
.ds-chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: 14px; font-size: 12px; color: #9ec2e6;
  border: 1px solid rgba(53, 160, 255, 0.25); background: rgba(20, 52, 88, 0.5);
}
.ds-chip.ok { color: #7ff0c0; border-color: rgba(46, 230, 168, 0.35); }
.ds-dot { width: 7px; height: 7px; border-radius: 50%; background: #f5b638; }
.ds-chip.ok .ds-dot { background: #2ee6a8; box-shadow: 0 0 8px rgba(46, 230, 168, 0.8); }
.ds-clock { font-size: 13px; color: #cfe4f7; font-variant-numeric: tabular-nums; display: flex; gap: 8px; }
.ds-dim { color: #6f90b3; margin-left: 3px; }
.ds-user { font-size: 12px; color: #9ec2e6; }
.ds-icon-button {
  width: 26px; height: 26px; display: grid; place-items: center; cursor: pointer;
  border-radius: 6px; color: #9ec2e6; background: rgba(20, 52, 88, 0.5);
  border: 1px solid rgba(53, 160, 255, 0.25);
}
.ds-icon-button:hover { color: #eaf4ff; border-color: rgba(53, 160, 255, 0.6); }
</style>
