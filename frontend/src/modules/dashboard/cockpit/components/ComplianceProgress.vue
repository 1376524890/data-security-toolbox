<script setup lang="ts">
/**
 * 合规检查完成情况: the board's overall coverage plus the four checks behind it.
 *
 * Each row prints the pair it was measured on (``numerator/denominator``) as a
 * tooltip, so a rate that looks low can be traced to the collection it came
 * from instead of being taken on faith. A check with no denominator says
 * "无数据" rather than 0% - nothing to measure is not a failure.
 */
import { computed } from 'vue'
import CockpitCard from './CockpitCard.vue'
import type { ComplianceBoard } from '../../../../types/dashboard'
import { cockpitColors } from '../chartTheme'

const props = defineProps<{ board: ComplianceBoard | null }>()
defineEmits<{ open: [] }>()

const checks = computed(() => props.board?.checks || [])
const rate = computed(() => props.board?.rate ?? null)
const passed = computed(() => props.board?.passed ?? 0)
const measured = computed(() => props.board?.measured ?? 0)

function tone(value: number | null): string {
  if (value === null) return cockpitColors.slate
  if (value >= 100) return cockpitColors.green
  if (value >= 60) return cockpitColors.amber
  return cockpitColors.red
}
function rateText(value: number | null): string {
  return value === null ? '无数据' : `${value}%`
}
function pair(item: { numerator: number; denominator: number }): string {
  return `${item.numerator} / ${item.denominator}`
}
</script>

<template>
  <CockpitCard title="合规检查完成情况" action="更多" @action="$emit('open')">
    <div class="cp">
      <div class="cp-head">
        <span class="cp-rate" :style="{ color: tone(rate) }">
          {{ rate === null ? '—' : `${rate}%` }}
        </span>
        <span class="cp-sub" v-if="rate !== null">已完成 {{ passed }} / {{ measured }} 项</span>
        <span class="cp-sub" v-else>尚无可用分母</span>
      </div>
      <div class="cp-track">
        <i :style="{ width: `${Math.max(0, Math.min(100, rate ?? 0))}%`, background: tone(rate) }" />
      </div>
      <ul class="cp-list">
        <li v-for="item in checks" :key="item.key" :title="`${item.detail}（${pair(item)}）`">
          <span class="cp-dot" :style="{ background: tone(item.rate) }" />
          <span class="cp-name">{{ item.label }}</span>
          <span class="cp-pair">{{ pair(item) }}</span>
          <span class="cp-value" :style="{ color: tone(item.rate) }">{{ rateText(item.rate) }}</span>
        </li>
        <li v-if="!checks.length" class="cp-empty">暂无检查项</li>
      </ul>
    </div>
  </CockpitCard>
</template>

<style scoped>
.cp { display: flex; flex-direction: column; gap: 12px; }
.cp-head { display: flex; align-items: baseline; gap: 10px; }
.cp-rate {
  font-size: 30px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums;
}
.cp-sub { font-size: 12px; color: var(--soc-text-muted); }
.cp-track { height: 8px; border-radius: 4px; background: var(--soc-panel-hover); overflow: hidden; }
.cp-track i { display: block; height: 100%; border-radius: 4px; transition: width 0.3s ease; }
.cp-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 7px; }
.cp-list li {
  display: grid; grid-template-columns: 8px 1fr auto 52px; align-items: center; gap: 8px;
  font-size: 12px;
}
.cp-dot { width: 8px; height: 8px; border-radius: 50%; }
.cp-name { color: var(--soc-text); }
.cp-pair { color: var(--soc-text-dim); font-variant-numeric: tabular-nums; font-size: 11px; }
.cp-value { text-align: right; font-weight: 700; font-variant-numeric: tabular-nums; }
.cp-empty { grid-template-columns: 1fr; color: var(--soc-text-dim); }
</style>
