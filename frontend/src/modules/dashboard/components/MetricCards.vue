<script setup lang="ts">
/**
 * The six headline cards. Each one carries its own change indicator, and the
 * indicator is derived from the server's today/yesterday counts — when
 * yesterday had no rows the card says "今日新增 N" instead of a percentage
 * against zero, which would read as +∞.
 */
import { computed } from 'vue'
import AnimatedNumber from './AnimatedNumber.vue'
import ScreenIcon from './ScreenIcon.vue'
import type { DashboardOverview, MetricWindow } from '../../../types/dashboard'

const props = defineProps<{ overview: DashboardOverview | null; duration?: number }>()

interface Card {
  key: string
  label: string
  icon: string
  tone: 'danger' | 'warning' | 'info' | 'asset' | 'sensitive' | 'success'
  value: number
  window?: MetricWindow
  sub: string
}

// Two spellings of each tone: the solid colour and an alpha tint, so the card's
// wash and glow never depend on ``color-mix`` being available in the browser
// driving the wall.
const toneColors: Record<Card['tone'], string> = {
  danger: '#ff4d5e', warning: '#f5b638', info: '#35a0ff',
  asset: '#22d3ee', sensitive: '#8b7cff', success: '#2ee6a8',
}
const toneTints: Record<Card['tone'], { soft: string; glow: string; edge: string }> = {
  danger: { soft: 'rgba(255,77,94,.14)', glow: 'rgba(255,77,94,.22)', edge: 'rgba(255,77,94,.55)' },
  warning: { soft: 'rgba(245,182,56,.14)', glow: 'rgba(245,182,56,.22)', edge: 'rgba(245,182,56,.55)' },
  info: { soft: 'rgba(53,160,255,.14)', glow: 'rgba(53,160,255,.22)', edge: 'rgba(53,160,255,.55)' },
  asset: { soft: 'rgba(34,211,238,.14)', glow: 'rgba(34,211,238,.22)', edge: 'rgba(34,211,238,.55)' },
  sensitive: { soft: 'rgba(139,124,255,.14)', glow: 'rgba(139,124,255,.22)', edge: 'rgba(139,124,255,.55)' },
  success: { soft: 'rgba(46,230,168,.14)', glow: 'rgba(46,230,168,.22)', edge: 'rgba(46,230,168,.55)' },
}
function toneStyle(item: Card) {
  return {
    '--tone': toneColors[item.tone],
    '--tone-soft': toneTints[item.tone].soft,
    '--tone-glow': toneTints[item.tone].glow,
    '--tone-edge': toneTints[item.tone].edge,
  }
}

const cards = computed<Card[]>(() => {
  const overview = props.overview
  if (!overview) return []
  const { alerts, incidents, findings, assets, probes, integrations } = overview
  return [
    {
      key: 'alerts', label: '安全告警', icon: 'alert', tone: 'danger', value: alerts.total,
      window: alerts, sub: `今日 ${alerts.today} · 未处置 ${alerts.open}`,
    },
    {
      key: 'incidents', label: '安全事件', icon: 'event', tone: 'warning', value: incidents.total,
      window: incidents, sub: `今日 ${incidents.today} · 待处理 ${incidents.open}`,
    },
    {
      key: 'findings', label: '检测发现', icon: 'finding', tone: 'info', value: findings.total,
      window: findings, sub: `今日 ${findings.today} · 高危 ${findings.high_risk}`,
    },
    {
      key: 'assets', label: '监控资产', icon: 'asset', tone: 'asset', value: assets.total,
      sub: `高风险 ${assets.high_risk} · 主机/数据库/应用`,
    },
    {
      key: 'sensitive', label: '敏感数据资产', icon: 'sensitive', tone: 'sensitive',
      value: assets.sensitive, sub: `数据资产 ${assets.data_assets} 项`,
    },
    {
      key: 'probes', label: '在线探针', icon: 'probe', tone: 'success', value: probes.online,
      sub: `总计 ${probes.total} · 离线 ${probes.offline} · 组件 ${integrations.healthy}/${integrations.total}`,
    },
  ]
})

function changeText(item: Card): string {
  const window = item.window
  if (!window) return ''
  if (window.delta_pct === null) {
    return window.today > 0 ? `今日新增 ${window.today}` : '今日无新增'
  }
  const arrow = window.delta_pct > 0 ? '↑' : window.delta_pct < 0 ? '↓' : '→'
  return `${arrow}${Math.abs(window.delta_pct)}% 较昨日`
}

function changeTone(item: Card): string {
  if (!item.window || item.window.delta_pct === null) return 'flat'
  if (item.window.delta_pct > 0) return 'up'
  if (item.window.delta_pct < 0) return 'down'
  return 'flat'
}
</script>

<template>
  <div class="ds-metrics">
    <div v-for="item in cards" :key="item.key" class="ds-metric" :style="toneStyle(item)">
      <div class="ds-metric-icon" :style="{ color: toneColors[item.tone] }">
        <ScreenIcon :name="item.icon" :size="24" />
      </div>
      <div class="ds-metric-body">
        <div class="ds-metric-label">{{ item.label }}</div>
        <div class="ds-metric-value" :style="{ color: toneColors[item.tone] }">
          <AnimatedNumber :value="item.value" :duration="duration" />
        </div>
        <div class="ds-metric-sub">
          <span v-if="changeText(item)" class="ds-change" :class="changeTone(item)">
            {{ changeText(item) }}
          </span>
          <span class="ds-metric-note">{{ item.sub }}</span>
        </div>
      </div>
    </div>
    <div v-if="!cards.length" class="ds-metric ds-metric-empty">指标加载中…</div>
  </div>
</template>

<style scoped>
.ds-metrics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; height: 100%; }
.ds-metric {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px; overflow: hidden;
  border-radius: 6px; border: 1px solid rgba(53, 160, 255, 0.18);
  background: linear-gradient(90deg, var(--tone-soft), transparent 62%), rgba(11, 30, 54, 0.86);
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.ds-metric:hover {
  border-color: var(--tone-edge);
  box-shadow: 0 0 18px var(--tone-glow);
}
.ds-metric-empty { grid-column: span 6; color: #5b7799; font-size: 12px; justify-content: center; }
.ds-metric-icon {
  width: 42px; height: 42px; border-radius: 8px; display: grid; place-items: center;
  background: rgba(9, 26, 48, 0.9); border: 1px solid rgba(53, 160, 255, 0.2);
}
.ds-metric-body { min-width: 0; flex: 1; }
.ds-metric-label { font-size: 12px; color: #9ec2e6; letter-spacing: 0.08em; }
.ds-metric-value { font-size: 30px; font-weight: 700; line-height: 1.15; font-variant-numeric: tabular-nums; }
.ds-metric-sub { display: flex; align-items: center; gap: 8px; font-size: 11px; overflow: hidden; white-space: nowrap; }
.ds-change { font-weight: 600; }
.ds-change.up { color: #ff7b86; }
.ds-change.down { color: #2ee6a8; }
.ds-change.flat { color: #8aa6c6; }
.ds-metric-note { color: #6f90b3; text-overflow: ellipsis; overflow: hidden; }
</style>
